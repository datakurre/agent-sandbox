# Cooperative Browser

Handing an agent a CDP port is a capability, not a convenience: the browser on
the far end fetches on your account, outside everything `--proxy` enforces
(see the warning in [Usage & Flags](usage.md#reaching-back-to-the-host-host-loopback-port)).
`agent-sandbox browser` exists to make that safe to hand out anyway — it
starts a browser that carries a deny-by-default allow list of its own.

## A cooperative browser: `agent-sandbox browser`

`agent-sandbox browser` starts a browser that carries an allow list of its own:

```console
$ agent-sandbox browser
browser: 'e4c1a80f' -- CDP on 127.0.0.1:9222, egress deny-by-default
browser: allowed: 127.0.0.1:3000
browser:   agent-sandbox ctl policy allow <host>:443 --browser e4c1a80f
browser:
browser: now run, keeping whatever flags you already use:
browser:   agent-sandbox --browser -- claude
```

`--browser` on the launcher is the other half: it finds the browsers this
command is running, maps each of their CDP ports, and tells the agent which is
which via `AGENT_SANDBOX_BROWSER_CDP_PORT` (see below). Start the browsers
first — the channel is established at launch and cannot be added to a running
sandbox.

It is the same `agent-sandbox-proxy` the sidecar runs, with the same policy
format, the same `ctl policy` commands, and the same traffic summary when the
browser closes. The profile is ephemeral and holds none of your logins.

With no arguments the allow list is **the loopback ports of the app under test,
and nothing else** — the ones `AGENTS.md` declares in its
[`[ports]` block](configuration.md), plus any the target sandbox already
publishes. The declaration is what makes the order above work: the browser
starts before the sandbox exists, so there is nothing to ask podman about yet.
Each port is allowed as `127.0.0.1:<port>` and as `localhost:<port>`, because
those are one app to everyone except a proxy.

You do not need `--ports` on the browser and you do not need to repeat the port
in `[network]`. A declared port the sandbox never publishes is still reachable
from this browser, so `[ports]` in a repo you do not trust is worth the same
glance as `[mounts]`.

`AGENTS.md` in the current directory is always consulted, the same way it is
for `[ports]`: its `[network]` block, if any, merges into the browser's allow
list without a flag. Widen it further, up front or while it runs:

```sh
agent-sandbox browser --allow example.com:443       # at start
agent-sandbox browser --policy development          # a reusable policy
agent-sandbox ctl policy allow example.com:443 --browser   # while it runs
```

`ctl policy allow --browser` updates both layers — the proxy within a second,
and the browser's own managed allow list, which Chromium re-reads.

| Flag | What it does |
| --- | --- |
| `--cdp-port PORT` | where CDP listens; walks up from 9222 if taken |
| `--allow HOST[:PORT]` | allow a domain, IP/CIDR or host:port; repeatable |
| `--policy NAME` | merge a host-owned policy, the same files the launcher's `--policy` takes |
| `--no-published-ports` | do not seed the allow list from ports at all — neither `AGENTS.md`'s `[ports]` nor a running sandbox's published ones |
| `--extension DIR` | load an unpacked extension; repeatable |
| `--no-extensions` | load none, including any built into the wrapper |
| `--keep-profile DIR` | reuse a profile directory instead of an ephemeral one |
| `--chromium PATH` | which browser to launch |
| `--name NAME` | name the session, for running several at once (see below) |
| `--no-policy-overlay` | skip the managed-policy layer (the proxy still applies) |

### Several users at once

Each browser is a separate profile, so running more than one is how you
simulate more than one user — two people in a shared document, a buyer and a
seller, an admin and a guest. Name them:

```console
$ agent-sandbox browser --name alice --keep-profile ~/.cache/browsers/alice
browser: 'alice' -- CDP on 127.0.0.1:9222, egress deny-by-default
...
$ agent-sandbox browser --name bob --keep-profile ~/.cache/browsers/bob
browser: 'bob' -- CDP on 127.0.0.1:9223, egress deny-by-default
browser: 2 browsers running; --browser picks up all of them:
browser:   agent-sandbox --browser -- claude
```

Start them **before** the sandbox: the channel is established at launch, so a
browser started afterwards is not reachable until the next one. `--browser`
resolves whatever is running at that moment, so the command does not change as
you add sessions — `--browser=alice,bob` narrows it if you want only some.

Ports are assigned by walking up from 9222, skipping any a live browser has
already claimed, so you do not have to allocate them yourself. `--cdp-port`
pins one if you want a fixed number.

Inside the sandbox, `AGENT_SANDBOX_BROWSER_CDP_PORT` carries each attached
browser's port in the same `alice=9222,bob=9223` shape `--browser` was given,
so an agent can say which user it is acting as by choosing the port. From a
script, connect to each port directly:

```python
alice = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
bob   = p.chromium.connect_over_cdp("http://127.0.0.1:9223")
```

`--keep-profile` is what makes a session outlive the browser: the named
directory keeps its cookies and logins, so "alice" is still signed in next time.
Without it every session starts logged out, which is the right default for a
disposable browser and the wrong one for a multi-user scenario you re-run.

Each session also has its own allow list, so widening one does not widen the
others:

```sh
agent-sandbox ctl policy allow shop.example:443 --browser alice
```

A name is required only when more than one browser is running; with one,
`--browser` alone is unambiguous. Names must be unique among live sessions —
reusing one is refused rather than silently attaching to it.

Chromium is deliberately **not** part of the default package, so a plain install
carries no browser closure. `agent-sandbox browser` uses a Chromium on `PATH`;
if there is none, run it with a pinned one:

```sh
nix run github:datakurre/agent-sandbox#browser
```

!!! warning "Two layers, and they are not equals"
    The proxy is the bound: the browser is launched with `--proxy-server`
    pointing at it, and it denies by default. A managed Chromium policy
    (`URLBlocklist`/`URLAllowlist`) is a second, coarser net over the same allow
    list, and it is best-effort — it needs `bwrap` to bind over Chromium's
    compile-time policy directory, and the command says so on stderr when it
    cannot. On most hosts that directory does not exist, so `/etc` is rebuilt
    for the browser alone: a tmpfs with every real entry bound back into it and
    the policy directory added, leaving the host's `/etc` untouched. Without
    it, a CDP client can create a browser context with a proxy
    of its own and bypass the first layer. The managed policy binds the agent
    driving CDP, not you: you own the machine and can edit the same directory.
    See [Trust model](trust-model.md).

### Extensions

`--extension DIR` loads an unpacked extension, repeatably. To have some loaded
every time, override the package:

```nix
(import ./default.nix { inherit pkgs lib; }).override {
  browserExtensions = [ ./my-extension ];
}
```

Nothing is loaded by default: nixpkgs packages no Chrome extensions, so a
default would mean pinning a release artifact from elsewhere, and the ephemeral
profile is better off minimal.

Both flags reach Chromium as `--load-extension` plus
`--disable-extensions-except`, which is also why the wrapper pins `chromium`
rather than `google-chrome`: branded Chrome removed the first in 137 and the
second in 139, so an extension list there would quietly do nothing. When the
managed-policy layer is active it additionally blocks installing anything else
into the profile. For a Web Store extension rather than an unpacked directory,
the managed-policy route is `ExtensionInstallForcelist`.

### Driving it: `AGENT_SANDBOX_BROWSER_CDP_PORT`

`--browser` sets `AGENT_SANDBOX_BROWSER_CDP_PORT` for you, which an agent reads
to connect a Playwright script to each browser via `connect_over_cdp` — see the
`browser` skill for the concrete snippet. A launch that never sets `--browser`
behaves exactly as it did before this existed.

The variable is the underlying interface and `--browser` is a shorthand over it,
so the long form still works if you want to pin exact ports:

```sh
agent-sandbox --host-loopback-port 9222 --host-loopback-port 9223 \
              -e AGENT_SANDBOX_BROWSER_CDP_PORT=alice=9222,bob=9223 -- claude
```

The two compose rather than fight: a `--host-loopback-port` you wrote yourself
for a browser's CDP port wins, remap included, and `--browser` advertises the
number that mapping puts it on **inside**. So
`--host-loopback-port 9222:19222 --browser` tells the agent 19222, which is
where the browser actually answers from in there.

`--shared-network` is a separate decision. It puts the sandbox on a bridge so
sibling containers can reach it by name, replacing pasta — so any pasta option
you wanted is given up with it. Publishing does not need it, and neither does
`--host-loopback-port`. So the shared network is opt-in and most sandboxes should
leave it off. `AGENT_SANDBOX_NETWORK` names the network when the flag is on.

### SELinux and host-loopback sockets

SELinux checks a Unix socket connection between the two processes' domains;
relabeling the socket file (`--selinux`) does not change that check, and the
`container_connect_any` boolean only covers TCP ports. A `container_t` process
connecting to a socket a host process listens on is denied by default.

The host-loopback bridge is therefore built the other way round: the sandbox
owns the socket for every `--host-loopback-port` mapping (and for the `--nix`
cache endpoint), and the launcher on the host dials *into* it, keeping a few
idle connections parked for new clients to claim. A host process connecting to
a container's socket is permitted by the default policy, so the bridge works on
an enforcing host without a local policy module. It still needs `--selinux`
(on by default on such a host), like every other bind there, so the sandbox
can create its sockets in the mounted directory.

If `--nix`'s bridge does not come up within a few seconds, the entrypoint
leaves the host cache out of `NIX_CONFIG`, so Nix commands go straight to
their other substituters instead of retrying an unreachable one.

`--selinux` follows the host: when SELinux is enforcing, the launcher applies
shared relabeling (`:z`) to built-in writable binds; otherwise they stay plain
`:rw`, so non-SELinux and permissive hosts see no relabel side-effects. Pass
`--selinux` or `--no-selinux` to override the detected default. Podman volume options passed via
`--podman-args` are preserved exactly as supplied.

`--selinux` relabels the *file* a socket is mounted as, but that alone is not
enough for `--ssh`. Unlike the loopback bridge, `--ssh` still connects from
the sandbox to a host listener. Connecting to a forwarded `SSH_AUTH_SOCK`
(including a gpg-agent SSH socket) is a separate `unix_stream_socket connectto`
check between the container's process context and the *listening agent's*
context, typically `unconfined_t` for a user's own `ssh-agent`/`gpg-agent`.
Default policy denies that regardless of the file's label, to stop containers
reaching arbitrary host IPC sockets. `container_connect_any` is not a Unix-socket
permission and does not resolve this denial.

If `ssh`/`ssh-add` inside the sandbox reports `Permission denied` right after
finding the socket (as opposed to "no such user" or "could not open a
connection"), look for the AVC:

```sh
sudo ausearch -m avc -ts recent | grep connectto
```

Read its `scontext` and `tcontext` before considering a local policy rule:
allowing `container_t` to connect to a broad host domain such as
`unconfined_t` grants access to every other socket that domain listens on. If
the audit log is empty, a `dontaudit` rule may be hiding the denial; rebuild
the policy without those rules while you reproduce, then restore it:

```sh
sudo semodule -DB
# reproduce the failed ssh-add, then:
sudo semodule -B
sudo ausearch -m avc -ts recent | grep connectto
```

The proxy sidecar is treated as infrastructure: it always runs with SELinux
labeling disabled for `/sidecar_policy` and `/sidecar_shared` so proxy
readiness does not depend on host relabeling flags.
