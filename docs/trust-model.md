# Trust model

By design, `agent-sandbox` includes options that pierce the sandbox boundary. Note that these give any agent running inside the container capabilities on the host:
- `--ssh` (opt-in): The agent can authenticate as you using your forwarded SSH identity (e.g. `git push` to your repos).
- `--gpg` (opt-in): The agent can sign commits or authenticate with any key held by your host GnuPG agent. Note that `agent-sandbox` protects your private key files by checking for them and gracefully failing the GNUPG directory mount if they are present on disk, but the forwarded GnuPG agent socket is still accessible.
- `--podman` (opt-in): Forwards the host rootless podman socket. The agent can use this to launch **sibling containers** on the host, which is equivalent to a full sandbox escape (e.g. `podman run -v /:/host ...`).

### Running Containers: `--podman` vs `--privileged`
If you want the agent to be able to run its own containers, `agent-sandbox` supports two distinct models:

1. **Nested Containers (Safe):** Pass `--privileged` when launching the sandbox. The sandbox image contains its own baked-in Podman stack. `--privileged` gives the sandbox container enough kernel permissions to run a securely isolated Podman daemon *inside* the sandbox. The agent cannot use this to escape to the host.
2. **Sibling Containers (Unsafe):** Pass `--podman` to forward your host's Podman socket into the sandbox. When the agent runs `podman run`, it talks to your host machine's Podman daemon. The container is created on the host alongside the sandbox. This does *not* require `--privileged`, but it allows the agent to control your host's containers and easily escape the sandbox. Use this only when you need the agent to interact with existing host infrastructure or leverage the host's image cache for performance.

## A guest kernel: `--krun`

`--krun` runs the sandbox as a KVM microVM. Requires read/write access to `/dev/kvm` (usually the `kvm` group) and a `crun` built with libkrun. Only the sandbox becomes a VM — the proxy sidecar and the port forwarders stay ordinary containers, so `--proxy` and every `agent-sandbox ctl` subcommand that works by label are unaffected.

- `agent-sandbox ctl attach` and `agent-sandbox ctl mounts` **do not work** against a `--krun` sandbox and refuse with an explanation. crun's libkrun handler implements no `exec`, so there is no way into a running guest; and a host-side bind mount lands in the VMM's mount namespace where the guest cannot see it. Run the shell as the sandbox's own command (`agent-sandbox --krun -- bash`), and declare mounts up front with `--podman-args -v ... --`.
- `--podman` is refused under `--krun`; `--privileged` and `--selinux` are accepted with a warning that they are unverified against a guest.

The boundary it adds is **additive, not substitutive** — this is the whole of what it is for, and it is easy to overstate.

libkrun's own security model is explicit that the guest and the VMM are one security context, and that containment must come from the host's mechanisms: namespaces. Under podman that context already exists and is exactly the one the sandbox has without the flag. So the boundaries sit in series:

```
agent process
  │  ← guest kernel (libkrunfw), reachable only through virtio + KVM ioctls
VMM (the sandbox container process)
  │  ← rootless userns + mount ns + netns + seccomp   ← what you already had
host
```

A guest-kernel privilege escalation lands the attacker as your unprivileged uid inside the same container the agent started in, facing the boundary that was always there.

What it closes: host-kernel privilege escalation from code the agent runs. That is the entire gain.

What it does **not** close:

- **None of the three flags above.** `--ssh` and `--gpg` hand out host capabilities; forwarding them into a VM forwards them into a VM. (`--podman` is refused outright under `--krun`.)
- **Nothing on egress.** The proxy topology, the policy file and the connection log are unchanged. Networking uses libkrun's Transparent Socket Impersonation, where the guest has no virtual NIC and the VMM performs its `connect()` calls — inside the same `--internal` network namespace, which has no route out. The firewall neither widens nor narrows.
- **Nothing on the workspace.** With `--workspace` the agent can write to your git repository, and code it plants there runs on your host later, as you, outside every boundary described here. For a careless or prompt-injected coding agent this is the operative risk, and no hypervisor addresses it.
- **Nothing against a podman, netns or userns misconfiguration**, since the VMM sits inside that same configuration.

Two things it changes that are easy to miss, both measured rather than assumed:

- **The agent is `uid 0` inside the guest.** `--userns=keep-id` maps the *VMM process* on the host; it does not reach the guest's own user namespace, so a process that is unprivileged uid 33500 in an ordinary sandbox is root in a `--krun` one. This is not an escalation on the host — files the guest writes still land as your uid, because the VMM performs the write — but "the agent runs unprivileged" stops being true inside the boundary, and anything relying on in-container uid separation should not.
- **SELinux confinement of the sandbox process is off.** `--krun` runs the sandbox with `--security-opt label=disable`, because the kernel refuses an SELinux domain transition once a process is multi-threaded and libkrun has already spawned the VM's threads by then. With labeling left on, the guest does not boot at all on an enforcing host. `--selinux` still relabels the bind mounts (`:z`). On an SELinux host, `--krun` therefore trades SELinux confinement of the sandbox process for a guest kernel under the agent.

Nested podman inside a `--krun` guest does not work out of the box, despite `--privileged`. The guest kernel has both `overlay` and `fuse`, so the obstacle is not kernel capability: podman sees uid 0, defaults its storage to `/var/lib/containers`, and virtio-fs declines to create that because the VMM writes as your unprivileged host uid. Pointing podman's graphroot somewhere under `/home/user` is the missing piece.

It is opt-in and should stay that way. The honest reasons to reach for it are running genuinely untrusted code, and nested `--privileged` workloads — and the second of those is currently unfinished, per the paragraph above.

## Proxy Details (`--proxy`)

The `[network]` block supports `allow` and `[[network.rules]]` for granular controls.
- **Default Policy**: The policy is always **deny by default**. To allow all traffic, specify `allow = ["*"]` or `allow = ["*:port"]`.
- **Wildcards**: Wildcards are supported for domains (e.g., `*.github.com:443`). A strict domain like `github.com:443` matches that exact domain and **does not** match subdomains like `status.github.com:443`. A wildcard matches both the subdomains and the apex, so `*.github.com:443` alone covers `github.com` as well.
- Domain matching is case-insensitive.
- **L7 Filtering (`[[network.rules]]`)**: Restricts HTTPS traffic by method and URL path. 
  - Rules use glob matching (`*` matches a single segment, `**` matches multiple).
  - L7 filtering requires MITM decryption. The proxy automatically activates MITM for domains with L7 rules.
- **Secret Injection**: When `--secrets` is passed, the launcher reads `~/.config/agent-sandbox/secrets.toml` and cross-references it with the `[[network.rules]]` blocks that name a `secret`. It then calls `secretspec export` on the host to fetch the actual secrets, delivering them to the sidecar via a read-only memory mount. Secrets never enter the sandbox environment.
  - **Scoped to the rule, not the host.** A secret is bound to the host, method and path the operator authorized, and the proxy injects it only into requests matching that route — decided per request, so a keep-alive connection carrying several requests is not one decision. A host can have other `[[network.rules]]` entries without a `secret`; those are proxied plainly. This matters because `AGENTS.md` is untrusted and controls the *other* rules on that host: it cannot widen where an authorized token goes. Matching uses the normalised path, so `..` segments and percent-encoding cannot move a secret off its route.
  - **Verbatim Copy-Pasting**: To authorize secret injection, the operator copies the exact `[[network.rules]]` block from `AGENTS.md` into `~/.config/agent-sandbox/secrets.toml`. Every field must match, the port included; an omitted field takes its default (`method = "GET"`, `path = "/"`, `header = "Authorization"`) and is then matched exactly rather than acting as a wildcard. If a secret is requested in `AGENTS.md` but not authorized, the launcher halts at startup and displays the exact snippet required.
  - Where two authorized routes could match the same request, the more specific wins: longest domain pattern, then longest path pattern, then an exact method over `*`.
  - Note that MITM secret injection only supports HTTP/1.1; h2-only clients will fail the TLS handshake.
- When L7 filtering is active, the launcher mounts a session CA and the entrypoint exports a merged trust bundle (`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) for in-sandbox clients. With no `[[network.rules]]` in the launch policy nothing is ever intercepted, so no CA is mounted and ordinary HTTPS stays end-to-end authenticated. The corollary is that an L7 rule added mid-session (`ctl proxy allow --l7`, or `h` in the TUI) has no CA behind it; both say so rather than leaving you with certificate errors. Declare the rule in `AGENTS.md` and relaunch.
- Non-secret HTTPS remains blind `CONNECT` + byte pump. Only domains subject to L7 filtering or secret injection are decrypted.
- **Relay Architecture**: When `--proxy` is combined with `--ssh` or `--gpg`, the direct socket mounts are replaced with a relay server running in the sidecar.
- An invalid `[network]` block, or an unknown key in one, refuses the launch rather than starting with a policy that silently allows more than you wrote. See [Configuration](configuration.md#rules-the-launcher-refuses) for the combinations that are rejected.
- `--proxy` with no `AGENTS.md` defaults to deny all.
- **A degraded start is a warning, not a failure.** If the proxy cannot prove egress within 30s it serves anyway and the launcher says so. No rule is relaxed by this; requests may simply fail.
- **Cannot be combined with publishing a port.** A published port puts the sandbox on a NAT bridge alongside the proxy's internal network, giving it egress that does not pass through the proxy at all; the launcher refuses the combination rather than filtering some traffic and letting the rest around.
- The proxy accounts each connection itself (host, byte counts each way, verdict), so metering adds no packet capture and no per-byte disk overhead.
- The traffic summary ranks hosts by volume, collapses the tail beyond 15 hosts, and lists denied and failed connections separately:

  ```
  === Network Summary ===  2m 6s · 87 connections · 24.9 MiB in / 362.9 KiB out

    HOST                   CONNS       SENT       RECV
    api.anthropic.com         64  265.2 KiB   11.3 MiB  ████████████
    registry.npmjs.org         8   11.7 KiB    9.5 MiB  ██████████
    github.com                11     86 KiB    4.1 MiB  ████

    ── denied ────────────────────────────────────────
    telemetry.example.com      3

    ── failed ────────────────────────────────────────
    proxy.example.com          1  (dns)
  ```

  Colour and the volume bars appear only on an interactive terminal, and are
  suppressed by `NO_COLOR`; redirected to a file or a pipe the report is plain
  text with no bar column, so `ctl net > file` stays parseable.

`--proxy` also makes these available while the sandbox runs:

- `agent-sandbox ctl status` — one screen: proxy mode, rule and traffic counts, ports.
- `agent-sandbox ctl net` / `net -f` — the summary above for the session so far, or a live feed.
- `agent-sandbox ctl logs [-f]` — the proxy's own log: the policy it started with, and every denial as it happens.
- `agent-sandbox ctl proxy show|allow|rm|reset|export|check` — read and change the policy of a **running** sandbox.
- A connection record is written when it *closes*, plus one when it opens, so a long-lived HTTPS tunnel appears as `in flight` under `── still open ──` rather than as traffic. Non-secret HTTPS stays opaque. Denied request heads are available only in the ephemeral `denied-requests.jsonl` stream used by the TUI; sensitive headers are redacted, request heads are capped at 16 KiB, and the stream is capped at 4 MiB.
- The connection log lives on a host temp directory for the lifetime of the session and is removed at exit. `--proxy` always prints the summary above when the session ends; what happens to the raw log is set by `--proxy-log LEVEL`:

  | `--proxy-log` | at exit |
  | --- | --- |
  | *(unset)* | if anything was denied or failed, offers to save the log to the current directory; on a non-interactive run it is kept at `$TMPDIR/agent-sandbox-connections-<pid>.jsonl` instead |
  | `off` | discarded |
  | `denied` | saved to the current directory if anything was denied or failed |
  | `all` | saved to the current directory every session |

  Saved logs are named `agent-sandbox-connections-<session>-<timestamp>.jsonl`, and the summary prints the path as a terminal hyperlink. `agent-sandbox-network-summary <log>` re-renders a saved log. `--proxy-log` implies `--proxy`.
- Neither the policy nor the log is reachable from inside the sandbox, so the agent can neither widen its own firewall nor edit the record of its traffic.
- The connection log is bounded at 16 MiB during a session. When a limit is reached, the oldest log contents are discarded; this prevents a busy or long-lived container from accumulating unbounded logs.
- To inspect an HTTPS method and path after a domain is denied at `CONNECT`, the operator may temporarily add an L7 placeholder rule such as `host = "pypi.org:443"`, `method = "GET"`, `path = "/noop"`. This permits the CONNECT/MITM inspection stage but keeps `/noop` and every other unmatched path denied. The operator should replace it with the observed path pattern or remove it after training.

### What the policy covers

The containment itself is separate from the policy: the sandbox gets a single interface on
an internal network with no route off it, so the proxy is the only reachable destination and
an agent that ignores `HTTP_PROXY` simply fails. Everything below is the *policy* applied at
the proxy. Two limits remain by design; they are described at the end of this section.

Rules match on host **and** port. The syntax requires both to be specified in the same string, e.g. `allow = ["github.com:443", "api.github.com:443"]`.

Denials will say which part refused the connection, so an allowed host on an unlisted port is distinguishable from a host that was never allowed:

```
proxy: deny github.com:8443 (port 8443 is not in allow_ports (configured: 80, 443, 22))
```

The same explanation — naming the specific rule, or absence of one, that decided the verdict — is what shows up per-row in `agent-sandbox ctl tui` and in `agent-sandbox ctl proxy check`.

Private and loopback destinations are refused by default under `--proxy`,
with or without any rule of your own — whether they are named directly
or reached through a hostname that resolves to one:
`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`,
`100.64.0.0/10`, `0.0.0.0/8`, `fc00::/7`, `fe80::/10` and `::1/128`. The sidecar itself still sits
on the host's default bridge network as well as the sandbox's internal one — that is how it
gets `HTTP_PROXY`-reachable and keeps a working resolver — so without this baseline the proxy
could otherwise be asked to reach your host and your LAN on the sandbox's behalf. It also
binds only its address on the sandbox's internal network for accepting connections, not that
bridge, so another container of the same user cannot use it as an open proxy either. Allow a
range back explicitly when you need it:

```toml
[network]
allow = ["10.0.0.0/8"]   # corporate git over the VPN
```

An IP CIDR block in `[network].allow` of equal or greater specificity than a deny wins, at the proxy *and* in
the sidecar's routing table: the kernel's longest-prefix match is the same rule the proxy
applies, so a re-allowed range is genuinely reachable rather than permitted by the policy and
then dropped by a route.

**The sidecar's own resolvers are always reachable, whatever the policy says.** Names are
resolved in the sidecar, by libc, before any rule is consulted, so a `deny_ips` range that
happens to contain your nameserver would otherwise blackhole resolution itself and fail
*every* request, not only the ones aimed at that range — and the startup egress probe cannot
catch it, because it runs before the routes are installed. The baseline `192.168.0.0/16`
alone covers a great many home resolvers. Exempting them is not a way out of the sandbox: the
sandbox has no route into the sidecar at all, its only egress is `CONNECT` to the proxy, and
the proxy still checks every resolved address against the policy's `deny_ips` ranges. A `CONNECT` aimed at your
resolver stays refused.

The host's `search` domains and resolver `options` travel with the nameservers, so an
unqualified name that resolves on the host resolves in the sandbox too.

Hostnames are normalised before matching, so a trailing dot (`github.com.`) and an
IPv4-mapped IPv6 literal (`[::ffff:10.0.0.1]`) match the same rules as their plain forms.
Deny lists are therefore enforcing rather than advisory, in every mode.

Two limits remain by design. First, non-secret HTTPS stays blind: unless a host is subject to L7 filtering or secret injection, traffic after `CONNECT` is opaque, so
allowing a relay-like host still allows what that host can reach. Second, egress is
`CONNECT`-only: UDP, QUIC/HTTP3, ICMP and raw TCP have no path out at all, which is why some
tools need `HTTP_PROXY` honoured explicitly (`NODE_USE_ENV_PROXY=1` is set for Node) and why
SSH is rewritten through a generated `ProxyCommand`.

### Changing the proxy policy mid-session

```console
$ agent-sandbox ctl proxy show
agent-sandbox-myrepo-4213
  policy      /tmp/agent-sandbox-policy-Xf3a91cD/policy
  default     deny  (only the rules below are reachable)
  allow_domains github.com                         AGENTS.md
  allow_ips     10.0.0.0/8                         AGENTS.md
  deny_ips      127.0.0.0/8                        AGENTS.md
  deny_ips      169.254.0.0/16                     AGENTS.md
  …

$ agent-sandbox ctl proxy allow api.openai.com
  allowed     api.openai.com                    domains
  reloading   the proxy applies this within a second

$ agent-sandbox ctl proxy allow 8443
  allowed     8443                              ports
  reloading   the proxy applies this within a second
```

`allow` infers what kind of entry you gave it — domain, address or port — and prints back
what it decided.

**Deny rules are built-in only.** There is no `proxy deny`, no `deny` key in `AGENTS.md`,
and no `--deny-*` flag: the only deny rules a policy carries are the baseline private and
loopback ranges the launcher writes into every session. They cannot be added to or removed,
either — a live edit that changes the `deny_ips` set is refused, so the ranges protecting
your host and your LAN are fixed for the life of the sandbox. This is deliberate redundancy:
the firewall is deny-by-default, so a deny rule is never needed to *close* anything, and the
baseline exists purely to keep the sidecar's own reachability from becoming the agent's.
To narrow something you allowed, use `proxy rm allow`/`rm l7`; to see why a target is
refused, `proxy check HOST[:PORT]`.

The baseline ranges appear in `show` as ordinary `deny_ips` rules attributed to `AGENTS.md`
— they are included in `policy.base` alongside any user rules and are therefore restored by
`reset`. `proxy export` omits them, since they are always enforced regardless of what
`AGENTS.md` declares and round-tripping them into a new config would be redundant.

An IP CIDR block in `[network].allow` of equal or greater specificity is the only way to
reach one of those ranges — and it is an *allow*, not a deny, which is why it remains
available: it is how a corporate git server over a VPN is reached.

Changes take effect for new connections within a second. Connections already established keep running: the proxy checks policy when a connection opens and does not re-check it afterwards, so tightening a rule does not cut a tunnel that is already up — end the session for that. `proxy show` says how many are open when it matters.

`reset` restores the `[network]` policy from `AGENTS.md` rather than emptying the rules, since an empty policy allows everything. The baseline denials are part of what it restores, so a reset cannot drop them either.
