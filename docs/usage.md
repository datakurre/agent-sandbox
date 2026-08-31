# Usage

`agent-sandbox` launches AI coding agents inside an isolated Podman container. All integrations — filesystem access, network, SSH keys, GPG — are **opt-in**. Run it with no flags to get a shell where nothing from your host is exposed.

### Examples

```sh
agent-sandbox opencode                           # opencode, no integrations (all opt-in)
agent-sandbox --workspace --ssh opencode         # opt in to workspace and SSH
agent-sandbox --workspace --proxy opencode       # workspace + deny-by-default network firewall
agent-sandbox --workspace --ssh opencode --no-ssh  # override: drop SSH back out
agent-sandbox --workspace copilot --name johndoe # use a custom ctl selector
agent-sandbox copilot                            # github-copilot-cli (copilot)
agent-sandbox antigravity                        # antigravity-cli (agy)
agent-sandbox codex                              # codex
agent-sandbox pi                                 # pi
agent-sandbox graph-agent                        # graph-agent (tui)
echo "prompt" | agent-sandbox --workspace --json --prompt - pi  # headless pi, JSON result
echo "prompt" | agent-sandbox --workspace --prompt - pi         # headless pi, agent's own output
agent-sandbox --workspace --json -- make build                  # deterministic command, streamed JSON
agent-sandbox opencode --selinux                 # enable :z on built-in writable binds
agent-sandbox                                    # interactive bash (every agent's binary on PATH)
agent-sandbox opencode -- devenv shell           # devenv shell replacing opencode cmd
agent-sandbox --privileged opencode              # nested podman inside container
```

`pi` is packaged as a real Nix derivation (`pi-coding-agent.nix`, `buildNpmPackage`
against the published `@earendil-works/pi-coding-agent` npm tarball) baked into the
image the same as every other agent, not fetched at launch. It previously resolved
through `npx -y @earendil-works/pi-coding-agent` at every run — depending on live,
unauthenticated registry.npmjs.org access for a basic feature, and breaking outright on
any registry hiccup (a transient `403`, seen in practice, not merely a hypothetical). The
npm fetch now happens once, at image build time; a container launch needs no
npm/network access to start `pi` at all, `--proxy` included.

### Override the container command

Everything after the `--` sentinel replaces the default command:

```sh
agent-sandbox                                    # interactive shell (every agent's binary on PATH)
agent-sandbox -- bash -c "nix build .# && echo done"
agent-sandbox opencode -- devenv shell           # devenv shell with opencode default cmd replaced
```

### Pass podman flags

To pass arguments directly to podman, use `--podman-args`. All arguments after `--podman-args` will be passed to podman until a `--` sentinel is reached, which marks the start of the container command.

There are also convenient shortcuts for common Podman flags, including `-e`/`--env`,
`-v`/`--volume`, `--mount`, `-p`/`--publish`, `--add-host`, `--env-file`,
`--hostname`, and `--tmpfs`.

```sh
agent-sandbox --privileged opencode               # enable nested podman
agent-sandbox --podman-args --network=host -- bash # host network
agent-sandbox --podman-args -v ./cache:/cache -- opencode
agent-sandbox -e MY_VAR=1 opencode                # pass environment variable
```

### Configuring Defaults via Nix

All integrations are **disabled by default**. If you are building downstream tooling, you can establish your own defaults by wrapping the `agent-sandbox` binary in Nix. 

Because the CLI evaluates arguments sequentially (the last flag provided wins), any flags added by `wrapProgram` can be overridden by the user at runtime. For example, if the wrapper adds `--ssh`, running `agent-sandbox --no-ssh` will successfully disable SSH forwarding.

Here is an example that restores the historical defaults of `agent-sandbox`:

```nix
agent-sandbox = pkgs.symlinkJoin {
  name = "agent-sandbox";
  paths = [ inputs.agent-sandbox.packages.${pkgs.stdenv.hostPlatform.system}.default ];
  nativeBuildInputs = [ pkgs.makeWrapper ];
  postBuild = ''
    wrapProgram $out/bin/agent-sandbox --add-flags "--workspace --ssh --git --gpg --devenv --nix --ports"
  '';
};
```

### Flags

Most flags in the table below have a corresponding `--no-flag` option (e.g., `--no-workspace`) to explicitly disable it. The exceptions are `--name`, `--policy`, `--krun-memory`, `--krun-cpus` and `--ports-any-interface`. Taking a value is not itself the reason: `--host-loopback-port` takes one and does have `--no-host-loopback-port`, which clears every mapping collected so far. For sandbox launches, `--policy` requires `--proxy`; passing it without `--proxy` refuses the launch rather than turning the proxy on implicitly. `--no-policy` is different from `--no-proxy`: it keeps the deny-by-default proxy and the workspace `AGENTS.md` policy, while skipping all host-owned policy files selected before it, including the implicit per-agent policy. A later `--policy NAME` re-enables host-owned policy loading. `agent-sandbox browser --policy NAME` is separate and uses the browser's own proxy. A `--no-proxy` after `--proxy --policy NAME` still turns the sandbox proxy off, dropping the policies with it. Since arguments are evaluated sequentially, passing `--ssh` followed by `--no-ssh` will leave the feature disabled. This is how user-provided command line arguments can override defaults built into the script via `wrapProgram`.

`--gpg-agent` and `--gpg-sign` were merged and removed; use `--gpg` / `--no-gpg`.

| Group | Flag | What it does |
| --- | --- | --- |
| Workspace & identity | `--workspace` | Mounts the host's current working directory into `/workspace/<dirname>`. |
| Workspace & identity | `--name NAME` | Uses `NAME` instead of a random session word as the sandbox's `ctl` selector. |
| Workspace & identity | `--ssh` | Forwards the host's `SSH_AUTH_SOCK` to the container and pre-populates `known_hosts`. |
| Workspace & identity | `--git` | Passes host Git configurations (with a blocklist) and identity env vars. |
| Workspace & identity | `--gpg` | Enables host GnuPG agent forwarding and git commit signing behavior. |
| Workspace & identity | `--gpg-private` | Exposes `~/.gnupg` even if it holds on-disk secret keys. |
| Workspace & identity | `--devenv` | Persists `~/.local/share/devenv` across sessions. |
| Workspace & identity | `--nix` | Mounts the host `/nix/store` for native Nix execution. |
| Container runtime | `--podman` | Forwards the host rootless Podman socket (sibling containers). See [Trust model](trust-model.md). |
| Container runtime | `--selinux` | Applies SELinux shared relabeling (`:z`) to ordinary writable binds in the sandbox container; special modes such as the Nix overlay are left unchanged. |
| Container runtime | `--krun` | Runs the sandbox as a KVM microVM with its own kernel, using `podman --runtime krun`. See [Trust model](trust-model.md). |
| Container runtime | `--krun-memory MiB` | Guest RAM (default `4096`). Values of 128 or below are rejected. |
| Container runtime | `--krun-cpus N` | Guest vCPUs (1–16). Defaults to the host CPU affinity count. |
| Network & firewall | `--proxy` | Isolates the container from the internet and routes HTTP(S)/SSH through a proxy that enforces the workspace `AGENTS.md` `[network]` policy, plus a matching `~/.config/agent-sandbox/policies/<agent>.toml` if one exists (unless `--no-policy` is given). Prints a per-host traffic summary when the session ends. See details below. |
| Network & firewall | `--policy NAME` | For sandbox launches, merges a host-owned reusable policy from `~/.config/agent-sandbox/policies/NAME.toml` additively with `AGENTS.md`; requires `--proxy` and may be repeated. The browser subcommand uses its own proxy. |
| Network & firewall | `--no-policy` | Keeps `--proxy` and the workspace `AGENTS.md` policy, but skips all selected and implicit host-owned policy files. A later `--policy NAME` re-enables them. |
| Network & firewall | `--secrets` | Uses `secretspec` to resolve and inject HTTP headers (e.g., `Authorization`) into the proxied requests each `[[network.allowed_routes]]` rule authorises — that rule's host, method and path, and no others. Requires `--proxy`. See [Configuration](configuration.md#secrets). |
| Ports & mounts | `--ports` | Honors `[ports]` declarations from `AGENTS.md`. |
| Ports & mounts | `--ports-any-interface` | Permits port binds outside of loopback interfaces. |
| Ports & mounts | `--shared-network` | Joins the shared bridge network so other containers can reach this one by name. See below. |
| Ports & mounts | `--browser` | Attaches every browser `agent-sandbox browser` is running: maps each of their CDP ports and tells the agent which is which. `--browser=alice,bob` picks some of them. See [Cooperative Browser](browser.md). |
| Ports & mounts | `--host-loopback-port PORT` | Makes the host's `127.0.0.1:PORT` reachable at the sandbox's own `127.0.0.1:PORT`, and exports the list as `$AGENT_SANDBOX_HOST_PORTS`. Repeatable; takes `HOST:SANDBOX`. See below. |
| Ports & mounts | `--mounts` | Honors `[mounts]` declarations from `AGENTS.md`. |
| Ports & mounts | `--agent-mounts` | Mounts every known agent's state; `--agent-mounts=a,b` mounts just those (plus any launched agent). |

A few flags are one-off pass-throughs rather than persistent toggles, so they have no `--no-flag` form:

| Flag | What it does |
| --- | --- |
| `-e NAME=VAL`, `--env NAME=VAL` | Injects an environment variable. |
| `-v SPEC`, `--volume SPEC` | Adds a Podman volume. Repeatable. |
| `--mount SPEC` | Adds a Podman mount. Repeatable. |
| `-p SPEC`, `--publish SPEC` | Publishes a container port. Repeatable. |
| `--add-host SPEC` | Adds a Podman host entry. Repeatable. |
| `--env-file PATH` | Loads environment variables from a file. |
| `--hostname NAME` | Sets the container hostname. |
| `--tmpfs SPEC` | Adds a Podman tmpfs mount. Repeatable. |
| `--privileged` | Enables nested podman inside the sandbox (safe — see [Trust model](trust-model.md)). |
| `--podman-args ... --` | Passes arguments straight through to `podman` until the `--` sentinel (including `-v/--volume` and `-p/--publish`). |

There is no `--port` flag: declare ports in `AGENTS.md` and pass `--ports`, or
publish one directly with `--podman-args -p HOST:CONTAINER --`. Prefer
`--ports`: it defaults each bind to loopback and refuses a wider one unless
`--ports-any-interface` is given, while a raw `-p HOST:CONTAINER` binds
`0.0.0.0` and exposes the port to the LAN.

`--ports` composes with `--proxy` as long as every bind is loopback. Publishing
is ingress — podman forwards into the proxy's internal network without giving
the sandbox a route out of it — so the egress policy is untouched. A bind the
rest of the network can reach is refused under `--proxy`, because anything out
there could pull whatever the agent chose to serve and the proxy would never see
it. A raw `-p` is refused under `--proxy` too: the launcher never parses it, so
it cannot tell the two cases apart.

Whichever you use, the server *inside* the sandbox must bind `0.0.0.0`.
Publishing forwards to the sandbox's interface address, so a server bound to the
sandbox's own `127.0.0.1` answers from inside and refuses from the host.

### Programmatic mode

`agent-sandbox` can be run non-interactively for integration with other tools.
Two independent flags replace the old single `--programmatic`: `--prompt -`
controls where the agent's input comes from, `--json` controls whether stdout
is machine-readable. `--json --prompt -` together reproduce the old
`--programmatic` exactly; each also works alone, and `--json` works with no
agent at all, on a plain `-- COMMAND`.

| Flag | What it does |
| --- | --- |
| `--prompt -` | Feeds the named agent its prompt from stdin instead of running it interactively, appending agent-specific prompt arguments. `-` (stdin) is the only supported value today. Requires an agent to be named. |
| `--json` | Switches stdout to machine-readable JSON and suppresses human-interactive stderr output. With `--prompt`: the whole run is captured and reported as one closing object once the agent exits — an agent turn is one unit of work, not a log to tail — and the agent is asked to speak JSON too (see below). Without `--prompt` (typically a `-- COMMAND`): one `{"type": "output", "stream": "stdout"\|"stderr", "line": ...}` object is printed per output line as it happens, so a long-running command still tails live, followed by the closing object. |
| `--no-json` | Undoes an earlier `--json` on the same command line. |
| `--model NAME` | Passes the specified model to the agent (e.g., `sonnet`, `opus`, `gemini-1.5-pro`). Requires `--prompt`. |
| `--provider NAME` | Selects the agent's inference provider. Requires `--prompt`. |
| `--session ID` | Resumes an existing agent session. Requires `--prompt`. |
| `--fork ID` | Forks from an existing agent session — resumes it, but records the continuation as a new session. Requires `--prompt`. |
| `--max-ai-credits NUMBER` | Caps the AI credits a single run may spend. Requires `--prompt`. |

Every one of these is mapped per agent in `agents.nix`, because the agents do
not agree on how to spell them: a session id is `--resume` to `claude` and
`graph-agent`, `--session-id` to `copilot`, `--conversation` to `antigravity`
and `--session` to `opencode` and `pi`. An agent that declares no mapping for a
flag **refuses the run** rather than being handed a spelling it would reject —
or, worse, one it would misread. What is supported today:

| Agent | `--model` | `--session` | `--fork` | `--provider` | `--max-ai-credits` |
| --- | --- | --- | --- | --- | --- |
| `opencode` | ✅ | ✅ | ✅ | — | — |
| `claude` | ✅ | ✅ | ✅ | — | — |
| `copilot` | ✅ | ✅ | — | — | — |
| `antigravity` | ✅ | ✅ | — | — | — |
| `codex` | ✅ | — | — | — | — |
| `pi` | ✅ | ✅ | ✅ | ✅ | — |
| `graph-agent` | ✅ | ✅ | — | — | — |

`--prompt` itself is mapped the same way, through `programmaticArgs` — and for
`opencode` that mapping is the `run` subcommand, not the top-level command's
`--prompt` flag: the top-level command is the TUI, which took `-` as the prompt
*text* and then tried to start an interface that has no terminal to start in.
Similarly, `graph-agent` runs interactive TUI by default (`graph-agent tui`) and
takes its prompt positionally rather than from stdin (`-`), so `--prompt` is not
mapped for it.

Two gaps are worth naming. `codex` resumes through `codex exec resume <id>`, a
subcommand that has to precede the prompt argument rather than follow it, which
the append-style mapping cannot express — so `--session` is refused for it
instead of mis-spelled. And no agent declares `--max-ai-credits`: `copilot` did
until github-copilot-cli 1.0.61, which now answers it with `error: unknown
option '--max-ai-credits'`, so the mapping was removed and the launcher flag
fails until a release brings the flag back.

A mapping is an argument list, and the user's value replaces a `{}` token in it
or is appended when there is none. That is what lets an agent whose flag *wraps*
its value be expressed at all — forking is `--resume ID --fork-session` for
`claude` and `--session ID --fork` for `opencode`, since both spell a fork as a
resume with a qualifier rather than as an id-taking flag of its own.

`agents.nix` is validated at build time against `agents-schema.json`
(`make -C tests/unit schema`, or the `agents-schema` flake check), which is what
catches a misspelled key that would otherwise default silently to "unsupported".

The closing object (`"type": "exit"`) carries `status`, `stdout`,
`stdout_format` and `stderr` on every `--json` run — `stdout`/`stderr` are the
full captured output under `--prompt`, and empty under a streamed `-- COMMAND`
run, where that text already went out as `"type": "output"` lines while the
command ran. A run that reaches the sandboxed process also carries `network`,
an object with `summary` (per `host:port` byte counts, connection counts and
verdict), `denied` (the refused requests) and `proposed_policy` (a pasteable
`[network]` block for rules added live, or for the denied hosts when there were
none) — empty when the launch had no `--proxy`. A launch that fails on policy
carries `policy_error` instead.

### The agent's own JSON: `jsonArgs`

Every agent here can emit machine-readable output of its own, and each spells
that differently too — `--format json` for `opencode`, `--output-format json`
for `claude`, `copilot` and `antigravity`, `--json` for `codex`, `--mode json`
for `pi`. `--json` splices in whichever the agent declares as `jsonArgs`, so one
flag means one thing all the way down: this run's stdout is for a machine.

That is what keeps the result out of double encoding. An agent asked for JSON
produces JSON; quoted into the envelope's `stdout` string it would arrive as
JSON *inside* JSON, every brace escaped and a second parse needed to reach it.
Instead the launcher parses it and splices the values in:

```json
{"type": "exit", "status": 0, "stdout_format": "json",
 "stdout": [{"type": "agent_start"}, {"type": "text", "text": "Hello!"}]}
```

`stdout` is always an **array** under `"stdout_format": "json"` — one element
per JSONL event, or a single element for an agent that prints one result object
— so a consumer can iterate it without knowing which shape its agent emits.
`jq '.stdout[] | select(.type == "text")'` works the same across all of them.

Two cases fall back to `"stdout_format": "text"`, where `stdout` is the string
it has always been: an agent with no `jsonArgs` (none today, but a newly added
agent may have none), and output that does not parse — a crash before the first
event, or a warning printed onto stdout. The fallback is all-or-nothing on
purpose: half an event stream reported as a clean array would be worse than the
text, which at least still contains the warning. `stdout_format` is on every
closing object, including a streamed `-- COMMAND` run's, where it is `"text"`.

Because the flags follow `--json` rather than `--prompt`, a plain `--prompt`
run — one whose answer a human reads — gets the agent's ordinary output.

## Reaching back to the host: `--host-loopback-port`

Publishing sends bytes one way. To reach a service the *user* runs on the host —
a browser's CDP port, say (see the `browser` skill) — name its port:

```sh
agent-sandbox --host-loopback-port 9222 -- bash
```

The host's `127.0.0.1:9222` is then reachable at the sandbox's own
`127.0.0.1:9222`. Nothing else on the host's loopback is, which is the point:
only the ports you name.

This is not on by default and there is no way to get it implicitly. Podman
passes pasta `--no-map-gw`, and the `host.containers.internal` entry it does set
up points at the host's *LAN* address, not its loopback, so it does not reach a
loopback-bound service either.

The flag is a bind-mounted unix socket with the launcher splicing each connection
to the host, **not** a route. That is why it composes with every network mode,
`--proxy` included — a route would have to be a network mode, and the sandbox's
is always already spoken for. It is TCP only.

The sandbox gets the mapped ports as `$AGENT_SANDBOX_HOST_PORTS`, so an agent
inside can test for the channel instead of learning it is missing from a refused
connection. Repeat the flag for more than one, and use `HOST:SANDBOX` when the
sandbox already has something on that number:

```sh
agent-sandbox --host-loopback-port 9222 --host-loopback-port 5432:15432 -- bash
```

!!! warning "This is a capability, not a convenience"
    Under `--proxy` a mapped port is a channel the sidecar never sees. What is
    listening on it fetches on its own account: a CDP port in particular hands
    the agent a fully-privileged, cookie-bearing browser on the host, so the
    egress policy no longer bounds what can be fetched. That is deliberate and
    opt-in — but only for the ports you named. See [Trust model](trust-model.md).

## A cooperative browser: `agent-sandbox browser`

Handing an agent a CDP port is a capability, not a convenience (see the
warning above). `agent-sandbox browser` starts a Chromium behind its own
deny-by-default allow list, seeded from `AGENTS.md`'s `[ports]` block, then
`--browser` attaches it to the sandbox:

```sh
agent-sandbox browser                            # start an allow-listed browser
agent-sandbox --workspace --browser -- claude    # attach it to the sandbox
```

See [Cooperative Browser](browser.md) for multi-user sessions, extensions,
CDP wiring, and the two-layer security model.

### Building a policy interactively

When starting a sandbox on a new codebase or with an unknown set of dependencies, you can build the proxy policy as you go:

1. **Start the Sandbox**: Run `agent-sandbox --proxy`. With no `[network]` block yet, requests are recorded and the ones that do not match a rule are denied.
2. **Open the TUI**: In a **separate terminal**, run `agent-sandbox ctl tui`. This interactive interface lists the requests the sandbox is making, including the denied ones.
3. **Approve**: Use the following keybindings to update the policy in real time:
   - `a`: Allow domain — or, on an SSH row, authorize the relay for that host
   - `h`: Allow HTTP route (domain + method + path) (creates a `[[network.allowed_routes]]` rule)
   - `A`: Allow IP
   - `v`: Switch between the live Connections view and denied requests
   - `r`: Switch to the Rules view — the live effective policy, with `x` to remove a rule (blocked for launch-time rules from `AGENTS.md`, host policies, or the built-in baseline)
   - `d`: Show sanitized details for the selected row, in the denied-requests view or the Connections view; use `↑`/`↓` to scroll and `Esc` to return
   - `c`: Clear the list of recorded denials
   - `q` or `Esc`: Quit the TUI
   - `Ctrl+C`: Quit the TUI — press twice within 2 seconds to confirm (a single press only shows a warning); also handles an external SIGINT sent to the process
4. **Save Rules**: When you've trained the proxy to your liking, export the complete active policy — the original `AGENTS.md` rules plus the live additions — with `agent-sandbox ctl policy export`. It prints a fenced ```` ```toml agent-sandbox ```` block, which is the form the launcher reads, so append it to the project's `AGENTS.md` (`agent-sandbox ctl policy export >> AGENTS.md`) and delete the `[network]` block it supersedes. Redirect with a single `>` only into a scratch file: it would truncate `AGENTS.md`, prose and all. For reusable rules, `agent-sandbox ctl policy export --plain` prints the same policy without the Markdown fence — that is what a `~/.config/agent-sandbox/policies/<name>.toml` file wants, launched with `--proxy --policy <name>`. When the sandbox exits, its summary also prints only the rules added live as copy-pasteable `allowed_hosts` and `[[network.allowed_routes]]` TOML.

The proxy sources are additive, and selected explicitly:

| Flags | Network policy |
| --- | --- |
| `--proxy` | The workspace `AGENTS.md`, plus `~/.config/agent-sandbox/policies/<agent>.toml` if it exists and `--no-policy` was not given |
| `--proxy --policy development` | The above, plus the named host-owned policy |

For sandbox launches, `--policy` requires `--proxy` — using it alone refuses
the launch. The browser subcommand has its own proxy and accepts
`agent-sandbox browser --policy NAME` without a sandbox `--proxy`. The option
may be repeated. Policy files are plain TOML and use the same declarative
`[network]` syntax as `AGENTS.md`:

```toml
[network]
allowed_hosts = ["github.com:443", "registry.npmjs.org:443"]
```

Startup groups policy discovery under an `agent-sandbox: startup` heading,
with indented `policy:` entries showing where policies were looked up (the
`~/.config/agent-sandbox/policies` directory, honoring `$XDG_CONFIG_HOME`) and
which files were actually loaded.

When both standard input and output are terminals, the launcher renders the
session lifecycle as one animated spinner/status line on standard error: it
shows sandbox startup, proxy readiness and network configuration when
applicable, then command startup until the container entrypoint has finished
initialization. The status line clears before the command's own prompt appears.
Entrypoint readiness waits indefinitely for its marker, or until Podman exits or
readiness checking fails. On exit it replaces
the line with closing, proxy shutdown, and resource removal before cleanup, then
summarizes successful cleanup as `closed (proxy stopped, resources released)`.
The status line is suppressed for non-interactive launches, so piped and
machine-readable use remains unchanged. The summary is shown only after cleanup
has completed.

At session exit, rules added live through the TUI or `agent-sandbox ctl policy allow` are printed as a TOML block. Add that block to `AGENTS.md` for project-specific persistence, or merge it into a policy file for reuse across projects.

The TUI tails the connection log and shows recently-denied hosts live (deduplicated, with a repeat count and the specific reason the policy denied them), so you can add the missing rule without leaving the dashboard. Press `v` to switch to the Connections view, which shows all recent allowed, denied, failed, and currently-open connections live. Press `d` on a row in either view to inspect it: the denied-requests view shows the latest sanitized request head — method, target, path, and non-sensitive headers — and the Connections view shows the row's own verdict, timings and byte counts, followed by that head when one was recorded for the destination. Request heads exist for denials only; an allowed HTTPS tunnel is never decrypted unless a route or secret rule covers it, and the detail pane says so rather than showing an empty box. The detail stream is ephemeral, capped at 4 MiB, and the TUI retains at most 200 rows in each view with one bounded detail per denied row. Rows won't offer `h` (allow HTTP route) unless a method was recorded for them — allow the domain first with `a`, then retry from inside the sandbox to trigger a real HTTP-route check. There is no `D` (deny) key, and no `ctl policy deny`: the firewall is deny-by-default, so denying something already-denied is a no-op. Use the Rules view (`r`, with `x` to remove) if you need to narrow a rule you added.

For an HTTPS domain denied at `CONNECT`, the encrypted method and path are not available yet. The TUI detail view suggests a temporary placeholder L7 rule to let the proxy terminate TLS and observe the real request:

```toml
[[network.allowed_routes]]
host = "pypi.org:443"
method = "GET"
path = "/noop"
```

Retry the request, inspect the resulting L7 denial, then replace `/noop` with the required path or path pattern. The placeholder path itself remains denied; remove the temporary rule when training is complete.

#### Relay denials in the TUI

The relay is a second gate, and it refuses requests the proxy never sees: under
`--proxy --ssh` the real `ssh` runs in the sidecar, authorized by
`allow_signing` rather than by a host/port rule. Those decisions appear in the
same denied-requests list, with `SSH` in the Method column and port `22` — the
port an `allowed_hosts` entry has to name, whatever port `ssh` itself dialled.
`a` on such a row writes both lines the grant needs:

```
allow_signing github.com
allow_host github.com:22
```

`relay-server` re-reads the policy on every call, so a retry works without
relaunching, and the exit summary renders the pair back as
`allowed_hosts = ["github.com:22"]` — one entry, from which a relaunch
re-derives `allow_signing`. `h` and `A` are refused on these rows: nothing
about a relay decision is HTTP, and it authorizes a host rather than an
address.

A refused **`gpg`** call is shown too, but read-only. Signing has no
destination for a policy to name, so it is enabled by launching with `--gpg`
and by nothing else; `a` says so rather than writing a rule that would not
help. `agent-sandbox ctl relay` remains the full record, including SSH calls
whose destination could not be read out of the command line — those have no
host to write a rule for, so the TUI leaves them out rather than offering a
fix it cannot deliver.

### Git Integration Details

When using Git inside the sandbox, be aware of how the integration flags interact:

- `--git` injects your effective Git configuration into the container using environment variables instead of mounting `.gitconfig`. Host-side `[include]` directives are evaluated and flattened on the host, while host-specific file paths (like `gpg.*.program`, credential helpers, global gitignore, and custom hooks) are automatically blocklisted so they don't break Git inside the container.
- `--gpg` is required for `--git` to also include commit signing. Without it, the sandbox explicitly disables signing (`commit.gpgsign = false`, `tag.gpgsign = false`) to prevent signing failures when the host's GnuPG agent is not forwarded.
- `--ssh` is required for `git pull` and `git push` to work with SSH remotes. It forwards your host's `SSH_AUTH_SOCK`. Because we avoid excessive host mounts, we do *not* mount your host's `known_hosts` file. An SSH session in a sandbox is non-interactive, so the alternative to knowing a host key in advance is not a prompt but either a hard failure or a silent trust-on-first-use accept of whatever answered — so the key has to come from somewhere explicit. Under `--proxy` that is `[[network.known_hosts]]` in `~/.config/agent-sandbox/trusted.toml`, and a policy that authorizes SSH to a host you have not declared a key for refuses the launch with the block to paste (see [Configuration](configuration.md#ssh-host-keys)). In interactive terminals, if the host is a known forge with published keys, `agent-sandbox` offers an interactive `[y/N/d/?]` prompt to automatically append the keys (with unified diff preview). Without `--proxy` there is no policy to authorize against, and the published keys for GitHub, GitLab and Bitbucket are used.
- Combined with `--proxy`, neither socket is mounted into the sandbox at all: a
  forwarded socket is a capability that does not pass the firewall. The sockets
  go to the proxy sidecar instead, and the sandbox reaches them through
  `relay-ssh`/`relay-gpg`, which the relay authorizes each independently:
  `relay-gpg` needs only `--gpg` itself — signing has no destination to name,
  so no `AGENTS.md` declaration is required, in a proxied sandbox exactly as in
  an unproxied one. `relay-ssh` still needs an explicit `allowed_hosts` entry
  on port 22 for the destination, e.g. `allowed_hosts = ["github.com:22"]`,
  since push/pull genuinely need to name a host; with no such entry `git push`
  is refused. `agent-sandbox ctl relay` shows both states and the decisions
  made against them.
- The authorized host keys are delivered to whichever side actually runs `ssh`.
  Unproxied, that is the sandbox's own `~/.ssh/known_hosts`. Under
  `--proxy --ssh` it is the sidecar, so `relay-server` reads the file the
  launcher wrote beside the policy and passes `-o UserKnownHostsFile=…`: the
  sandbox's copy would be on the wrong side of the boundary, and the sidecar
  runs as `root`, whose home is `/root` rather than the image's `HOME`.
- The relay refuses an `ssh` that tries to decide any of this for itself:
  `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking`,
  `VerifyHostKeyDNS`, and `-F` (an alternate config could set any of them out
  of sight). It also refuses `-J` / `ProxyJump`, which would pass the
  destination check and then connect somewhere else. If a host's key is not
  trusted, the fix is a `[[network.known_hosts]]` entry in `trusted.toml`, not
  a flag — that is the whole point of having the file.

### Bundled OpenCode skills

The image includes five OpenCode skills at `/home/user/.agents/skills`:

- `agent-sandbox` for the sandbox itself: recognising that it is running in one,
  what the firewall, the ephemeral home directory and the opt-in flags imply, and
  which host-side command to ask the user for when it hits a limit. It also
  covers `secretspec.toml` and how `--secrets` injects credentials the sandbox
  never sees.
- `nix` for running any nixpkgs tool ad hoc, without installing it.
- `nix-flake` for `flake.nix`: packaging software, outputs, checks, and simple
  `nix develop --command` development shells.
- `devenv` for `devenv.nix`: declarative environments with language toolchains
  and supporting services, entered with `devenv shell -- <command>`.
- `browser` for browser automation, in both shapes: headless inside the sandbox
  from nixpkgs, and the cooperative host browser `agent-sandbox browser` starts.
  It covers screenshotting a page for visual analysis, driving it via
  Playwright, and which of the two browsers a given task wants.

Each skill is a `SKILL.md` with the common path plus reference files with
advanced patterns. `nix-flake` additionally carries `uv2nix.md` (packaging
Python projects that have a `uv.lock`) and `images.md` (building OCI container
images from a flake package); `agent-sandbox` carries `network.md` (proxy policy
syntax, the `ctl` loop, live-versus-relaunch changes) and `secretspec.md`;
`browser` carries `reference.md` (form filling, the raw CDP fallback, and a
debugging checklist).

They are bundled into the image rather than mounted by the launcher. To use
user-owned skills instead, mount a replacement tree with
`--podman-args -v HOST:/home/user/.agents/skills --` or declare the mount in
`AGENTS.md` under `[mounts]`. A more specific child mount can replace only one
bundled skill. The canonical tree is also linked from
`~/.claude/skills`, `~/.codex/skills`, `~/.copilot/skills`, `~/.cursor/skills`,
`~/.gemini/skills`, and `~/.gemini/config/skills` for tools that use those
discovery paths.

## Managing running sandboxes

`agent-sandbox ctl` operates on the host, on sandboxes already running:

| Command | What it does |
| --- | --- |
| `load` | build the image and import it into podman |
| `list [-a] [--roles]` | running sandboxes and their proxy mode; `--roles` also shows the proxy sidecars |
| `status [WORD] [--sandbox WORD]` | one screen per sandbox, pointing at the commands below |
| `net [-f] [WORD] [--sandbox WORD]` | connection summary, or a live feed |
| `logs [-f] [--tail N] [WORD] [--sandbox WORD]` | the proxy sidecar's log |
| `tui [WORD] [--sandbox WORD]` | interactive terminal UI: shows denied requests live so you can add the missing rule, a Connections view (`v`) of all recent connections including currently-open ones, plus a Rules view (`r`) to inspect and remove existing rules, without leaving the dashboard |
| `policy show\|allow\|rm\|reset\|export\|check [WORD] [--sandbox WORD]` | read and change the policy of a running sandbox; `export` prints its `[network]` section as a fenced AGENTS.md block (`--plain` for a bare-TOML policy file); `check HOST[:PORT]` dry-runs whether a target would be allowed |
| `mounts ls\|add\|rm\|export [WORD] [--sandbox WORD]` | inspect and manage bind mounts into a running sandbox; `export` prints its `[mounts]` section as AGENTS.md TOML |
| `relay [-f] [WORD] [--sandbox WORD]` | show whether GPG signing is enabled and which hosts SSH push/pull may reach, plus what the relay has been asked for |
| `attach [WORD] [-- CMD...]` | execute an interactive command inside a running sandbox, with the environment the entrypoint built (see below) |
| `browser [WORD] [--sandbox WORD]` | start a throwaway host browser behind a deny-by-default allow list, for cooperative testing over CDP; `--name` runs several at once (see below) |
| `purge [--all] [-n] [-f]` | reclaim leftovers; running sandboxes are kept unless `--all`, and `-f` skips the confirmation |

New sandboxes are shown by a single session word, such as `silent`. Use that
word with any targetable command, either positionally or as `--sandbox silent`.
The full Podman name remains internal. `--name johndoe` replaces the random word
with `johndoe`, so the same commands accept `johndoe` explicitly:

```console
$ agent-sandbox --workspace copilot --name johndoe
$ agent-sandbox ctl attach johndoe
$ agent-sandbox ctl status --sandbox johndoe
```

Names use letters, numbers, `.`, `_`, and `-`, and cannot already be in use.
If the same selector is present on more than one sandbox, the command refuses
to guess and prints the matching workspaces and full names. The selector may be
omitted when exactly one running sandbox matches the current directory. This
implicit lookup depends on `--workspace`; a sandbox launched with only
`--name johndoe` still works with explicit `ctl ... johndoe` commands, but has
no workspace label for bare local lookup.

For example:

```console
$ agent-sandbox ctl status silent
$ agent-sandbox ctl net --sandbox silent
$ agent-sandbox ctl logs silent
$ agent-sandbox ctl policy show --sandbox silent
$ agent-sandbox ctl mounts ls --sandbox silent
$ agent-sandbox ctl attach silent -- bash
```

`attach` reproduces the environment the sandbox's own session runs in. `podman
exec` would otherwise start from the container's *configured* environment — what
`podman run` was given — and so miss everything the entrypoint derived at
startup: the merged CA bundle, `GIT_SSH_COMMAND=relay-ssh`, and the flattened
host git config from `--git`. That is why `git clone git@github.com:…` used to
fail in an attached shell while the same clone worked in the session the
launcher started. The entrypoint records those variables at
`~/.config/agent-sandbox/env` and `attach` passes them back in; a sandbox from an
older image simply has no such file and attaches as before.

`purge` defaults to leftovers only: exited sandboxes, sidecars whose sandbox is
gone, per-session networks nothing is attached to, and temp directories from a
launcher that was killed before it could clean up. `-n` shows what it would
remove.
