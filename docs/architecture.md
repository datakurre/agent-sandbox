# Architecture

`agent-sandbox` is a Nix flake that produces a rootless Podman container image
("agent-sandbox") together with a launcher binary (`agent-sandbox`) and a
management multiplexer (`agent-sandbox ctl`, with the subcommands `load`,
`list`, `status`, `net`, `logs`, `tui`, `proxy`, `ports`, `mounts`, `attach`, `relay` and `purge`).

## What's in the image

| Category      | Tools                                                |
| ------------- | ---------------------------------------------------- |
| AI coding     | opencode, claude-code, github-copilot-cli (copilot), antigravity-cli (agy) |
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

A bash script that wraps `podman run`.  Call flow:

1. Parse flags: consume known flags (`--ssh`, `--no-git`, `--no-workspace`,
   etc.), pass through `-v` volume mounts (with relative-path expansion),
   stop at `--` sentinel.
 2. Build mounts array from toggles (ssh socket, git config, gpg socket,
    devenv dir, podman host socket, CWD workspace) plus the state dirs of
    whichever agents are selected — the positionally-launched one by default,
    or the set chosen via `--agent-mounts`/`--agent-mounts=…` — sourced from
    `agents.nix` (opencode, claude-code, copilot, antigravity).
3. Build env_args array from toggles (SSH_AUTH_SOCK, git identity,
   CONTAINER_HOST, DOCKER_HOST, TERM, COLORTERM).
4. Create ephemeral `/etc/passwd` and `/etc/group` with the host user's uid/gid.
5. Call `podman run` with `--userns=keep-id`, tmpfs for `~/.config`,
   `~/.cache`, `~/.local`, all mounts and env vars, then the image and the
   final command (default `opencode`, overridable via `-- …`).

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

The proxy itself is Rust (`proxy/src/main.rs`, `ipnet` its only dependency): a
thread-per-connection HTTP forward proxy handling `CONNECT` and absolute-form
requests.  Policy decisions happen once per connection, before the byte pumps
start; an established tunnel is never re-evaluated.

Three directories, and which side can see them is the design:

| Path | Mounted into | Contents |
| --- | --- | --- |
| `/sidecar_policy` | sidecar, **read-only** | `policy`, `policy.base` |
| `/sidecar_shared` | sidecar only | `proxy-ready`, `ready`, `egress-degraded`, `connections.jsonl` |
| `/sidecar_secrets` | sidecar, **read-only** | `bindings` |
| (host temp dirs) | — | removed by the launcher's exit trap |

Neither is mounted into the sandbox. That is deliberate and load-bearing: the
agent must not be able to widen the firewall that contains it, nor rewrite the
log of what it did. Changing policy is therefore a host-side operation
(`agent-sandbox ctl proxy`), which is why the old in-container
`agent-sandbox-allow` was deleted rather than repaired.

**Policy format.** The proxy enforces the `[network]` block from `AGENTS.md`.
`[network].allow` and `[network].deny` contain domains, wildcard domains, IPs, or CIDR blocks.
`[network].ports` contains port ranges.
`[[network.http]]` configures L7 paths and optional secret injection.

`agent-sandbox-proxy --check-policy FILE` is the single reference validator:
`parse_agents.py` writes the file, the proxy reads it, the host-side `proxy`
command vets its own writes with the same binary, and `checks.firewall-policy`
tests the whole chain.  There is no second implementation to drift.

**Secret Injection.** `--secrets` triggers secret injection via `secretspec`.
The source of authority is a host-controlled TOML file (`~/.config/agent-sandbox/secrets.toml`),
which defines the exact bindings (domain, header, secret). The launcher runs
`agent-sandbox-resolve-secrets`, which cross-references this config with the policy's
`secret_domains` from `AGENTS.md`, and then runs `secretspec export` on the host
to fetch the values. The filtered bindings are then written to `/sidecar_secrets/bindings`,
which the sidecar reads. The proxy handles actual header injection. When a `secret` field is provided in a `[[network.http]]` block in `AGENTS.md`, `parse_agents.py` automatically populates the `secret_domains`
policy list with their domains, removing the need for manual duplication.

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
