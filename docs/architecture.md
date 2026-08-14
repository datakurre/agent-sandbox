# Architecture

`agent-sandbox` is a Nix flake that produces a rootless Podman container image
("agent-sandbox") together with a launcher binary (`agent-sandbox`) and a
management multiplexer (`agent-sandbox ctl`, with the subcommands `load`,
`list`, `status`, `net`, `logs`, `tui`, `proxy`, `mounts`, `attach`, `relay` and `purge`).

## What's in the image

| Category      | Tools                                                |
| ------------- | ---------------------------------------------------- |
| AI coding     | opencode, claude-code, github-copilot-cli (copilot), antigravity-cli (agy), codex |
| Shell / tools | bash, coreutils, ripgrep, fd, jq, curl, wget, …     |
| Languages     | python3, uv, nodejs, gnumake, gcc libs               |
| Git / GitHub  | git, gh                                              |
| Nix           | nix, devenv                                          |
| Containers    | podman, crun, conmon, skopeo, slirp4netns,           |
|               | fuse-overlayfs, docker→podman alias                  |
| Editor        | vim                                                  |

Podman container config files (`containers.conf`, `storage.conf`,
`registries.conf`, `policy.json`) are baked in at `/etc/containers/`, so
nested rootless podman is pre-configured when the sandbox is launched with
`--privileged`.

## Image (`image` attr in `default.nix`)

Built with `pkgs.dockerTools.streamLayeredImage` (`maxLayers = 2`).  All tools are baked into a
`buildEnv` and compressed into a minimal number of layers (2) to optimize `podman load` speed and container
startup latency. They are registered in the Nix store database so `nix` / `devenv` / Nix
builtins inside the container work without re-substituting store paths.

Key layers:

| Path                  | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `/etc/nix/nix.conf`   | `sandbox = false`, `flakes` enabled                    |
| `/etc/containers/*`   | Pre-configured rootless podman (crun, overlay driver)  |
| `/usr/bin/env`        | Symlink to coreutils `env` for generic shebangs        |
| `/lib64/ld-linux-*`   | ELF interpreter for prebuilt npm binaries              |
| `/home/user`          | Home directory (uid/gid mapped at runtime)             |
| `/workspace`          | Default working directory                              |

## Entrypoint (`agent-sandbox-entrypoint`)

1. Loads the Nix store registration on first start (unless `AGENT_SANDBOX_HOST_NIX=1`, in which case the host's `/nix` mount is used, or `AGENT_SANDBOX_SKIP_NIX_INIT=1`, which sidecar launches set because they do not need Nix bootstrap).
2. Sets up `known_hosts` for common git forges to avoid first-time connection prompts.
3. When `AGENT_SANDBOX_GPG_AGENT=1`, symlinks the forwarded host gpg-agent
   socket into `~/.gnupg/S.gpg-agent`.
4. When `HTTP_PROXY` is set, compensates for tools that don't honor it on
   their own: dynamically generates `~/.ssh/config` to route SSH through the
   proxy, and sets `NODE_USE_ENV_PROXY=1` so Node's core `http`/`https` and
   built-in `fetch` (undici) stop dialing out directly — this also covers
   the bundled Node-based agent CLIs, which share Node's runtime. An
   operator's own explicit `NODE_USE_ENV_PROXY` setting is left alone.
5. `exec "$@"`.

## Launcher (`agent-sandbox`)

A Rust binary (`cli/src/bin/agent-sandbox.rs`) that wraps `podman run`; the
per-integration fragments it assembles live in `cli/src/launch.rs`, where they
are unit-tested without a podman.  Call flow:

1. Parse flags: consume known flags (`--ssh`, `--no-git`, `--no-workspace`,
   etc.), collect `--podman-args` up to the `--` sentinel, stop at `--`.
 2. Build the mounts array from toggles (ssh socket, gpg socket, devenv dir,
    podman host socket, CWD workspace) plus the state dirs of whichever agents
    are selected — the positionally-launched one by default, or the set chosen
    via `--agent-mounts`/`--agent-mounts=…` — sourced from `agents.nix`
    (opencode, claude-code, copilot, antigravity, codex).
3. Build the env array from toggles (SSH_AUTH_SOCK, the flattened git config
   and identity, CONTAINER_HOST, DOCKER_HOST, TERM, COLORTERM).
4. Add `[ports]` and `[mounts]` declared in `AGENTS.md` (`cli/src/agents.rs`),
   under `--ports`/`--mounts`.  An invalid block refuses the launch.
5. Create ephemeral `/etc/passwd` and `/etc/group` with the host user's uid/gid,
   and name the container `agent-sandbox-<workspace>-<word>`, where the word is
   the selector every `ctl` command accepts.
6. Call `podman run` with `--userns=keep-id`, tmpfs for `~/.config`,
   `~/.cache`, `~/.local`, all mounts and env vars, then the image and the
   final command (`bash` by default, the selected agent's command when one is
   named positionally, and anything after `--` overrides both).

`--git` passes the host's *effective* configuration as `GIT_CONFIG_*`
environment variables rather than mounting `.gitconfig`: `[include]` directives
are evaluated on the host, and keys naming a host-only path (`gpg.*.program`,
credential helpers, `core.excludesFile`, `core.hooksPath`) are dropped, since
inside the container they would resolve to nothing.  The variables are passed
indirectly, as `AGENT_SANDBOX_GIT_CONFIG_*`, so the entrypoint can append its
own entry after them — which is how a signing override wins over the host's
`commit.gpgsign`.

## Loader (`agent-sandbox ctl load`)

`podman load < ${image}`

## Proxy sidecar (`--proxy`)

`--proxy` makes the launcher start a second container from the same image,
running `agent-sandbox-sidecar`, and put the sandbox on a `podman network create
--internal --disable-dns` network with no route off-host.  The sidecar is
dual-homed on that network and on `bridge`, so it is the sandbox's only path to
the internet, and the sandbox gets `HTTP_PROXY`/`HTTPS_PROXY` pointing at its
**address**.

**`--disable-dns` is load-bearing.**  Podman routes a container's whole resolver
through aardvark-dns as soon as *any* of its networks has `dns_enabled` --
`podman-run(1)`, under `--dns`: "passing a custom network whose `dns_enabled` is
set to `true` to `--network` will result in `/etc/resolv.conf` only referring to
the aardvark-dns server".  And aardvark has refused to serve `--internal`
networks since 1.11.0 ("Do not allow 'internal' networks to access DNS"), so the
sidecar's only nameserver would answer NXDOMAIN to every external name: every
request 502s with `dns: Name or service not known`.  Passing `--dns` does not
help, because those servers are demoted to an aardvark upstream that aardvark
then declines to use -- which is why that fix looked right and did nothing.  This
has now been diagnosed three times; with DNS off on both of the sidecar's
networks there is no aardvark in the path and `--dns` lands in `resolv.conf`
verbatim.

The corollary is that `HTTP_PROXY` names an IP, not the sidecar's container name:
without aardvark there is nothing to resolve that name.  That also retires a race
nothing ever gated on -- the readiness handshake never proved aardvark had
published the sidecar's record before the sandbox started.

The proxy itself is Rust (`proxy/src/main.rs`): a thread-per-connection HTTP
forward proxy handling `CONNECT` and absolute-form requests, terminating TLS for
the hosts that carry an L7 rule.  Policy decisions happen once per connection,
before the byte pumps start; an established tunnel is never re-evaluated.

Three directories, and which side can see them is the design:

| Path | Mounted into | Contents |
| --- | --- | --- |
| `/sidecar_policy` | sidecar, **read-only** | `policy`, `policy.base`, `policy.baseline` |
| `/sidecar_shared` | sidecar only | `proxy-ready`, `ready`, `egress-degraded`, `ca.pem`, `connections.jsonl`, `denied-requests.jsonl`, `relay.jsonl` |
| `/sidecar_secrets` | sidecar, **read-only** | `bindings` |
| (host temp dirs) | — | removed when the launcher exits |

None of them is mounted into the sandbox — `ca.pem` is bound in as a single
file, not by exposing its directory. That is deliberate and load-bearing: the
agent must not be able to widen the firewall that contains it, nor rewrite the
log of what it did. Changing policy is therefore a host-side operation
(`agent-sandbox ctl proxy`), which is why the old in-container
`agent-sandbox-allow` was deleted rather than repaired.

**Policy format.** The proxy enforces the `[network]` block from `AGENTS.md`.
`[network].allow` contains domains, wildcard domains, IPs, or CIDR blocks, each
with a port or port range.  `[[network.rules]]` configures L7 routes and
optional secret injection.  Those two keys are the whole surface: an unknown key
under `[network]` refuses the launch rather than being ignored.

The launcher compiles that block into the flat, line-oriented policy file the
proxy reads (`allow_domains`, `allow_ips`, `allow_ports`, `allow_l7`,
`secret_l7`, `allow_signing`, `deny_ips`, `default`), which is also the
format `agent-sandbox ctl proxy` edits in place.  `secret_l7` records a
*route* -- `domain<TAB>method<TAB>path`, like `allow_l7` -- not a domain, and
`deny_ips` is written only by the launcher: there is no domain deny list, and
a live edit that changes the deny set is refused.  `agent-sandbox-proxy
--check-policy FILE` validates it: the launcher writes the file, the proxy reads
it, and the host-side `proxy` command vets its own writes with the same parser,
so there is no second implementation to drift.

**Secret Injection.** `--secrets` triggers secret injection via `secretspec`.
The source of authority is a host-controlled TOML file
(`~/.config/agent-sandbox/secrets.toml`), which defines the exact bindings --
host and port, method, path, secret, header, prefix. The launcher calls the
resolver in `cli/src/secrets.rs`, which cross-references that config with the
policy's `secret_l7` routes from `AGENTS.md`, and then runs `secretspec export`
on the host to fetch the values. The filtered bindings are written 0600 into
`/sidecar_secrets/bindings`, which only the sidecar mounts, as
`domain<TAB>method<TAB>path<TAB>header<TAB>value`.

The route travels with the binding, and that is the design.  `AGENTS.md` is
untrusted and controls the *other* rules on a host, so recording only the
domain -- verifying the operator's method and path host-side and then throwing
them away -- meant a second, secret-less rule (`method = "*", path = "/**"`)
collected the same token.  `inject::proxy_http1_with_injection` now resolves the
binding *per request*, after the L7 check and against the same normalized path,
so a keep-alive connection carrying several requests is several decisions and
`/user/repos/../../zen` cannot carry the token to `/zen`.

**CA trust.** The proxy terminates TLS for any host carrying an L7 rule, using a
CA it generates per session and writes to `/sidecar_shared/ca.pem`. The launcher
binds *that file alone* into the sandbox and points
`AGENT_SANDBOX_PROXY_CA_FILE` at it; the entrypoint merges it with the image's
bundle into `~/.cache` and exports the result under every variable the usual
clients read. The directory itself is never mounted into the sandbox — the
connection log lives there.

The mount is gated on the launch policy actually carrying an `allow_l7` line.
With none, `skip_l7` is true for every host and the leaf issuer is never
reached, so a CA in the sandbox's trust store would grant the proxy the ability
to intercept anything for no purpose. The cost is that an L7 rule added
mid-session has no CA behind it; `ctl proxy allow --l7` and the TUI's `h` warn
rather than failing later at certificate validation.

The launcher appends a baseline `deny_ips` list (loopback, RFC1918, link-local,
CGNAT, ULA) to every policy it writes, under `--proxy`.

**Relay Architecture.** When `--ssh` or `--gpg` are used with `--proxy`, the sandbox cannot mount the host sockets directly (they bypass the proxy firewall). Instead, the sidecar runs `relay-server`, exposing a TCP port to the sandbox. Inside the sandbox, `relay-ssh` and `relay-gpg` binaries forward requests to the sidecar over a custom binary protocol.
The sidecar sits on the default bridge as well as the sandbox's internal network,
so without it a policy with no rules -- which is exactly what a bare `--proxy` runs -- could
be asked to reach the host and its LAN on the sandbox's behalf.  Writing it as
ordinary `deny_ips` entries rather than compiling it into the proxy means one
list, visible in `proxy show`, restored by `reset`, and mirrored into the
kernel routes by the same `sync_routes` that handles user rules.
An `allow_ips` entry of equal or greater specificity overrides one of them; that
is why `is_denied_address` breaks prefix ties toward allow.

`sync_routes` mirrors that whole rule, not `deny_ips` alone.  The kernel's
longest-prefix match *is* the specificity comparison the proxy makes, so every
`allow_ips` entry gets a route via the default gateway and beats a shorter
blackhole by itself; the one case a routing table cannot express is the
equal-prefix tie, there being room for a single route per prefix, and that is
handled by not installing the blackhole at all.  Until it did this, a re-allowed
range -- including the README's own `allow_ips = ["10.0.0.0/8"]` against the
baseline -- was permitted by the proxy and then dropped on the floor by the
route, with `proxy show` reporting the rule as in force.

The sidecar's nameservers, read from its own `/etc/resolv.conf`, are exempted
unconditionally.  Resolution happens in the sidecar via libc, before any rule is
consulted, so a `deny_ips` range containing the resolver blackholes DNS itself
and fails every request rather than only the ones aimed at that range -- and the
baseline's `192.168.0.0/16` does exactly that to a home router.  This is not a
way out: the sandbox has no route into this netns, its only egress is CONNECT to
the proxy, and `is_denied_address` still runs over every resolved address, so a
CONNECT aimed at the resolver stays refused.

Because the sidecar is on that bridge, the proxy binds only the address it holds
on the internal network, selected by subnet membership from `SIDECAR_SUBNET`
rather than by interface name -- podman's eth0/eth1 assignment follows the order
of the `--network` flags and is not something to depend on.

**Startup ordering** matters and is why there are two readiness markers: the
proxy validates policy, probes egress and writes `proxy-ready`; the sidecar then
installs the routes and writes `ready`; only then does the launcher start the
sandbox.  So routes are in place before any traffic can exist, and a bad policy
exits 2 before touching the kernel table.

The corollary is that the probe runs *before* the routes exist and so cannot
catch a policy that blackholes the sidecar's own resolver: it proves egress,
`sync_routes` then breaks it, and the session 502s with a clean startup behind
it.  That is why the nameserver exemption above is unconditional rather than a
reaction to a failed probe.  Reordering the markers would not help either --
proving egress after the routes are installed would only turn a silent failure
into a degraded launch, when the routes can simply be right.

The egress probe is never fatal -- a degraded launch beats a hung one -- but it
is no longer silent: when it gives up it writes `egress-degraded` with the
resolver's own error, and the launcher prints that on the terminal.  Without it
the session looks healthy for 30 seconds and then 502s, which is exactly how the
aardvark problem above stayed hidden.

**Runtime changes.** The proxy polls the policy file's `(mtime, size)` once a
second and swaps an `Arc<ProxyConfig>` under an `RwLock`, clearing the DNS cache
with it; the sidecar reconciles the blackhole routes against the kernel on the
same interval.  A rejected or vanished policy keeps the one already in force.
New connections see the change within a second; established ones do not.
