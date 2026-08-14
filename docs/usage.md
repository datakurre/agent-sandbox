# Usage

### Override the container command

Everything after the `--` sentinel replaces the default command:

```sh
agent-sandbox                                    # interactive shell (every agent's binary on PATH)
agent-sandbox -- bash -c "nix build .# && echo done"
agent-sandbox opencode -- devenv shell           # devenv shell with opencode default cmd replaced
```

### Pass podman flags

To pass arguments directly to podman, use `--podman-args`. All arguments after `--podman-args` will be passed to podman until a `--` sentinel is reached, which marks the start of the container command.

There are also convenient shortcuts like `--privileged` and `-e` for common podman flags.

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

Every flag in the table below has a corresponding `--no-flag` option (e.g., `--no-workspace`) to explicitly disable it. Since arguments are evaluated sequentially, passing `--ssh` followed by `--no-ssh` will leave the feature disabled. This is how user-provided command line arguments can override defaults built into the script via `wrapProgram`.

`--gpg-agent` and `--gpg-sign` were merged and removed; use `--gpg` / `--no-gpg`.

| Group | Flag | What it does |
| --- | --- | --- |
| Workspace & identity | `--workspace` | Mounts the host's current working directory into `/workspace/<dirname>`. |
| Workspace & identity | `--ssh` | Forwards the host's `SSH_AUTH_SOCK` to the container and pre-populates `known_hosts`. |
| Workspace & identity | `--git` | Passes host Git configurations (with a blocklist) and identity env vars. |
| Workspace & identity | `--gpg` | Enables host GnuPG agent forwarding and git commit signing behavior. |
| Workspace & identity | `--gpg-private` | Exposes `~/.gnupg` even if it holds on-disk secret keys. |
| Workspace & identity | `--devenv` | Persists `~/.local/share/devenv` across sessions. |
| Workspace & identity | `--nix` | Mounts the host `/nix/store` for native Nix execution. |
| Container runtime | `--podman` | Forwards the host rootless Podman socket (sibling containers). See [Trust model](trust-model.md). |
| Container runtime | `--selinux` | Applies SELinux shared relabeling (`:z`) to writable binds in the sandbox container. |
| Container runtime | `--krun` | Runs the sandbox as a KVM microVM with its own kernel, using `podman --runtime krun`. See [Trust model](trust-model.md). |
| Container runtime | `--krun-memory MiB` | Guest RAM (default `4096`). Values of 128 or below are rejected. |
| Container runtime | `--krun-cpus N` | Guest vCPUs (1–16). Defaults to the host CPU affinity count. |
| Network & firewall | `--proxy` | Isolates the container from the internet and routes HTTP(S)/SSH through a proxy that enforces `AGENTS.md`'s `[network]` policy if present. Prints a per-host traffic summary when the session ends. See details below. |
| Network & firewall | `--secrets` | Uses `secretspec` to resolve and inject HTTP headers (e.g., `Authorization`) into proxied traffic matching `secret_domains`. Requires `--proxy`. |
| Ports & mounts | `--ports` | Honors `[ports]` declarations from `AGENTS.md`. |
| Ports & mounts | `--ports-any-interface` | Permits port binds outside of loopback interfaces. |
| Ports & mounts | `--mounts` | Honors `[mounts]` declarations from `AGENTS.md`. |
| Ports & mounts | `--agent-mounts` | Mounts every known agent's state; `--agent-mounts=a,b` mounts just those (plus any launched agent). |

A few flags are one-off pass-throughs rather than persistent toggles, so they have no `--no-flag` form:

| Flag | What it does |
| --- | --- |
| `-e NAME=VAL`, `--env NAME=VAL` | Injects an environment variable. |
| `--privileged` | Enables nested podman inside the sandbox (safe — see [Trust model](trust-model.md)). |
| `--proxy-log off\|denied\|all` | What to do with the proxy's connection log when the session ends; implies `--proxy`. Unset, a session that had denials offers to save one. See [Trust model](trust-model.md). |
| `--podman-args ... --` | Passes arguments straight through to `podman` until the `--` sentinel (including `-v/--volume` and `-p/--publish`). |

There is no `--port` flag: declare ports in `AGENTS.md` and pass `--ports`, or
publish one directly with `--podman-args -p HOST:CONTAINER --`. Either way,
publishing a port cannot be combined with `--proxy`.

By default, built-in writable binds stay plain `:rw` so non-SELinux hosts see
no relabel side-effects. On SELinux hosts, pass `--selinux` to apply shared
relabeling (`:z`) to built-in writable binds. Podman volume options passed via
`--podman-args` are preserved exactly as supplied.

`--selinux` relabels the *file* a socket is mounted as, but that alone is not
enough for `--ssh`: connecting to a forwarded `SSH_AUTH_SOCK` (including a
gpg-agent SSH socket) is a separate `unix_stream_socket connectto` check
between the container's process context and the *listening agent's* context —
typically `unconfined_t` for a user's own `ssh-agent`/`gpg-agent` — and
default policy denies that regardless of the file's label, to stop containers
reaching arbitrary host IPC sockets. If `ssh`/`ssh-add` inside the sandbox
reports `Permission denied` right after finding the socket (as opposed to "no
such user" or "could not open a connection"), confirm with
`sudo ausearch -m avc -ts recent | grep connectto` and, if it names your agent
socket, allow it host-wide with:

```
sudo setsebool -P container_connect_any 1
```

This is a persistent, host-wide SELinux policy change, so it is not something
`agent-sandbox` can or should apply on your behalf.

The proxy sidecar is treated as infrastructure: it always runs with SELinux
labeling disabled for `/sidecar_policy` and `/sidecar_shared` so proxy
readiness does not depend on host relabeling flags.

### Building a policy interactively

When starting a sandbox on a new codebase or with an unknown set of dependencies, you can build the proxy policy as you go:

1. **Start the Sandbox**: Run `agent-sandbox --proxy`. With no `[network]` block yet, requests are recorded and the ones that do not match a rule are denied.
2. **Open the TUI**: In a **separate terminal**, run `agent-sandbox ctl tui`. This interactive interface lists the requests the sandbox is making, including the denied ones.
3. **Approve**: Use the following keybindings to update the policy in real time:
   - `a`: Allow domain
   - `h`: Allow HTTP route (domain + method) (creates a `[[network.rules]]` rule)
   - `A`: Allow IP
   - `v`: Switch between the live Connections view and denied requests
   - `r`: Switch to the Rules view — the live effective policy, with `x` to remove a rule (blocked for rules that came from `AGENTS.md`)
   - `d`: Show sanitized details for the selected denial; use `↑`/`↓` to scroll and `Esc` to return
   - `q` or `Esc`: Quit the TUI
4. **Save Rules**: When you've trained the proxy to your liking, export the active rules by running `agent-sandbox ctl proxy export > AGENTS.md` (or append them to your existing `[network]` blocks).

The TUI tails the connection log and shows recently-denied hosts live (deduplicated, with a repeat count and the specific reason the policy denied them), so you can add the missing rule without leaving the dashboard. Press `v` to switch to the Connections view, which shows all recent allowed, denied, failed, and currently-open connections live. Press `d` on a row to inspect the latest sanitized request head, including its method, target, path, and non-sensitive headers. The detail stream is ephemeral, capped at 4 MiB, and the TUI retains at most 200 rows in each view with one bounded detail per denied row. Rows won't offer `h` (allow HTTP route) unless a method was recorded for them — allow the domain first with `a`, then retry from inside the sandbox to trigger a real HTTP-route check. There is no `D` (deny) key, and no `ctl proxy deny`: the firewall is deny-by-default, so denying something already-denied is a no-op. Use the Rules view (`r`, with `x` to remove) if you need to narrow a rule you added.

For an HTTPS domain denied at `CONNECT`, the encrypted method and path are not available yet. The TUI detail view suggests a temporary placeholder L7 rule to let the proxy terminate TLS and observe the real request:

```toml
[[network.rules]]
host = "pypi.org:443"
method = "GET"
path = "/noop"
```

Retry the request, inspect the resulting L7 denial, then replace `/noop` with the required path or path pattern. The placeholder path itself remains denied; remove the temporary rule when training is complete.

### Git Integration Details

When using Git inside the sandbox, be aware of how the integration flags interact:
- `--git` injects your effective Git configuration into the container using environment variables instead of mounting `.gitconfig`. Host-side `[include]` directives are evaluated and flattened on the host, while host-specific file paths (like `gpg.*.program`, credential helpers, global gitignore, and custom hooks) are automatically blocklisted so they don't break Git inside the container.
- `--gpg` is required for `--git` to also include commit signing. Without it, the sandbox explicitly disables signing (`commit.gpgsign = false`, `tag.gpgsign = false`) to prevent signing failures when the host's GnuPG agent is not forwarded.
- `--ssh` is required for `git pull` and `git push` to work with SSH remotes. It forwards your host's `SSH_AUTH_SOCK`. Because we avoid excessive host mounts, we do *not* mount your host's `known_hosts` file. Instead, we pre-populate the container's `~/.ssh/known_hosts` with the public keys for GitHub, GitLab, and Bitbucket so first-time connections do not prompt for verification.
- Combined with `--proxy`, neither socket is mounted into the sandbox at all: a
  forwarded socket is a capability that does not pass the firewall. The sockets
  go to the proxy sidecar instead, and the sandbox reaches them through
  `relay-ssh`/`relay-gpg`, which the relay authorizes against the policy's
  `allow_signing` list — declare an SSH port to populate it, e.g.
  `allow = ["github.com:22"]`. With no such entry the relay refuses every
  request; `agent-sandbox ctl relay` shows the list and the decisions made
  against it.

### Examples

```sh
agent-sandbox opencode                           # opencode, everything on
agent-sandbox opencode --no-ssh                  # drop an integration
agent-sandbox copilot                            # github-copilot-cli (copilot), everything on
agent-sandbox antigravity                        # antigravity-cli (agy), everything on
agent-sandbox opencode --no-workspace            # no CWD mount
agent-sandbox opencode --selinux                 # enable :z on built-in writable binds
agent-sandbox                                    # interactive bash (every agent's binary on PATH)
agent-sandbox opencode -- devenv shell           # devenv shell replacing opencode cmd
agent-sandbox --privileged opencode              # nested podman inside container
```

## Managing running sandboxes

`agent-sandbox ctl` operates on the host, on sandboxes already running:

| Command | What it does |
| --- | --- |
| `load` | build the image and import it into podman |
| `list [-a] [--roles]` | running sandboxes and their proxy mode; `--roles` also shows sidecars and forwarders |
| `status [WORD] [--sandbox WORD]` | one screen per sandbox, pointing at the commands below |
| `net [-f] [WORD] [--sandbox WORD]` | connection summary, or a live feed |
| `logs [-f] [WORD] [--sandbox WORD]` | the proxy sidecar's log |
| `tui [WORD] [--sandbox WORD]` | interactive terminal UI: shows all recent connections live, including currently-open and denied ones, plus denied-request actions and a Rules view (`r`) |
| `proxy show\|allow\|rm\|reset\|export\|check [WORD] [--sandbox WORD]` | read and change the policy of a running sandbox; `export` prints its `[network]` section as AGENTS.md TOML; `check HOST[:PORT]` dry-runs whether a target would be allowed |
| `mounts ls\|add\|rm\|export [WORD] [--sandbox WORD]` | inspect and manage bind mounts into a running sandbox; `export` prints its `[mounts]` section as AGENTS.md TOML |
| `relay [-f] [WORD] [--sandbox WORD]` | show the SSH/GPG relay's `allow_signing` policy and what it has been asked for |
| `attach [WORD] [-- CMD...]` | execute an interactive command inside a running sandbox |
| `purge [--all] [-n]` | reclaim leftovers; running sandboxes are kept unless `--all` |

New sandboxes are shown by a single session word, such as `silent`. Use that
word with any targetable command, either positionally or as `--sandbox silent`.
The full Podman name remains internal. If the same word is present on more than
one sandbox, the command refuses to guess and prints the matching workspaces and
full names. The word may be omitted when only one sandbox is running or when
exactly one matches the current directory.

For example:

```console
$ agent-sandbox ctl status silent
$ agent-sandbox ctl net --sandbox silent
$ agent-sandbox ctl logs silent
$ agent-sandbox ctl proxy show --sandbox silent
$ agent-sandbox ctl mounts ls --sandbox silent
$ agent-sandbox ctl attach silent -- bash
```

`purge` defaults to leftovers only: exited sandboxes, forwarders and sidecars
whose sandbox is gone, per-session networks nothing is attached to, and temp
directories from a launcher that was killed before it could clean up. `-n` shows
what it would remove.
