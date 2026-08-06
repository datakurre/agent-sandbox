# agent-sandbox

Sandboxed AI coding environment that runs inside a rootless Podman container.
Launch `opencode` (or any other tool) and explicitly opt-in to integrations like
SSH forwarding, GPG signing, Git identity, host Podman socket, and `devenv` state.

## Install

### From a local clone

```sh
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#          # installs agent-sandbox and agent-sandbox-ctl
```

### From a remote flake

```sh
nix profile add github:datakurre/agent-sandbox
```

After installing, build the container image (one-time):

```sh
agent-sandbox-ctl load
```

## Usage

```
agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]
```

To launch `opencode`, use `agent-sandbox opencode`. This launches it inside the sandbox with
the current working directory mounted at `/workspace` and every integration
enabled. If the current directory contains a `devenv.nix`, opencode is started
through a devenv shell (`devenv shell -- opencode .`) so project dependencies
are loaded automatically. Running `agent-sandbox` with no arguments prints the help menu.

### Override the container command

Everything after the `--` sentinel replaces the default command:

```sh
agent-sandbox -- bash                            # interactive shell
agent-sandbox -- bash -c "nix build .# && echo done"
agent-sandbox opencode -- devenv shell           # devenv shell with opencode mounts
```

### Pass podman flags

To pass arguments directly to podman, use `--podman-args`. All arguments after `--podman-args` will be passed to podman until a `--` sentinel is reached, which marks the start of the container command.

There are also convenient shortcuts like `--privileged` and `-e` for common podman flags.

```sh
agent-sandbox --privileged opencode               # enable nested podman
agent-sandbox --podman-args --network=host -- bash # host network
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
    wrapProgram $out/bin/agent-sandbox --add-flags "--workspace --ssh --git --gpg-agent --gpg-sign --devenv --nix --ports"
  '';
};
```

### Flags

Every flag has a corresponding `--no-flag` option (e.g., `--no-workspace`) to explicitly disable it. Since arguments are evaluated sequentially, passing `--ssh` followed by `--no-ssh` will leave the feature disabled. This is how user-provided command line arguments can override defaults built into the script via `wrapProgram`.

- `--workspace`: Mounts the host's current working directory into `/workspace/<dirname>`.
- `--ssh`: Forwards the host's `SSH_AUTH_SOCK` to the container.
- `--git`: Mounts host Git configurations and passes identity env vars.
- `--gpg-agent`: Forwards the host GnuPG agent socket for commit signing.
- `--gpg-sign`: Sets git config to enable commit signing inside the container.
- `--gnupg-private`: Exposes `~/.gnupg` even if it holds on-disk secret keys.
- `--devenv`: Persists `~/.local/share/devenv` across sessions.
- `--nix`: Mounts the host `/nix/store` for native Nix execution.
- `--podman`: Forwards the host rootless Podman socket (sibling containers).
- `--selinux`: Applies SELinux shared relabeling (`:z`) to writable binds.
- `--firewall`: Isolates the container from the internet and routes HTTP(S) traffic through a domain-filtering proxy based on the `[proxy]` block in `AGENTS.md`. Non-HTTP(S) traffic is blocked.
  - The `[proxy]` block supports `allow_domains`, `deny_domains`, `allow_ips`, and `deny_ips`.
  - **Default Policy**: 
    - If you provide any allow list (`allow_domains` or `allow_ips`), the default policy becomes **deny all**.
    - If you only provide deny lists (`deny_domains` or `deny_ips`), the default policy is **allow all**.
  - **Simultaneous Allow & Deny (Most Specific Wins)**: You can specify both allow and deny rules at the same time. When a target matches both, the **more specific rule wins**:
    - For domains, the longer pattern wins (e.g., an explicit rule for `api.github.com` overrides a wildcard rule for `*.github.com`).
    - For IPs, the longer CIDR prefix wins (e.g., `10.1.0.0/24` overrides `10.0.0.0/8`).
  - **Wildcards**: Wildcards are supported for domains (e.g., `*.github.com`). Note that a strict domain like `github.com` only matches that exact domain and **does not** match subdomains like `status.github.com`. To match both, you must specify both `github.com` and `*.github.com`. This applies to both allow and deny domain rules.
- `--meter-network`: Isolates the container from the internet, routes HTTP(S) traffic through a proxy, and captures it for a post-run summary. Non-HTTP(S) traffic is blocked.
- `--ports`: Honors `[ports]` declarations from `AGENTS.md`.
- `--ports-dynamic`: Allows `agent-sandbox-ctl port add` post-launch.
- `--ports-any-interface`: Permits port binds outside of loopback interfaces.

You can use `--port [HOST:]CONTAINER[/PROTO]` to publish a port.

You can pass `-e NAME=VAL` or `--env NAME=VAL` to inject environment variables.

You can also pass `-v` / `-v*` volume mounts before `--`.  Relative paths in
the source are resolved against `$PWD`; relative destinations are prefixed with
`/workspace/`.

By default, built-in writable binds stay plain `:rw` so non-SELinux hosts see
no relabel side-effects.  On SELinux hosts, pass `--selinux` to apply shared
relabeling (`:z`) to built-in writable binds.  User-provided `-v` options are
preserved exactly as supplied.

### Examples

```sh
agent-sandbox opencode                           # opencode, everything on
agent-sandbox opencode --no-ssh                  # drop an integration
agent-sandbox copilot                            # github-copilot-cli (copilot), everything on
agent-sandbox antigravity                        # antigravity-cli (agy), everything on
agent-sandbox opencode --no-workspace            # no CWD mount
agent-sandbox opencode --selinux                 # enable :z on built-in writable binds
agent-sandbox -- bash                            # interactive bash without agent-specific mounts
agent-sandbox opencode -- bash                   # interactive bash with opencode configs mounted
agent-sandbox opencode -- devenv shell           # devenv shell with opencode configs mounted
agent-sandbox --privileged opencode              # nested podman inside container
```

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

## How it works

1. `agent-sandbox-ctl load` imports the OCI image (built with `pkgs.dockerTools.streamLayeredImage`) into the host's podman image store.
2. `agent-sandbox` calls `podman run` with `--userns=keep-id`, tmpfs mounts for ephemeral home subdirectories, explicit bind mounts for persistent state (opencode, devenv, …), and forwarded sockets (ssh, gpg, podman).
3. A slim entrypoint loads the Nix store registration so `nix` commands work from the start, sets up the gpg-agent symlink when requested, then `exec`s the container command.

## Trust model

By design, `agent-sandbox` includes options that pierce the sandbox boundary. Note that these give any agent running inside the container capabilities on the host:
- `--ssh` (on by default): The agent can authenticate as you using your forwarded SSH identity (e.g. `git push` to your repos).
- `--gpg-agent` (on by default): The agent can sign commits or authenticate with any key held by your host GnuPG agent. Note that `agent-sandbox` protects your private key files by checking for them and gracefully failing the GNUPG directory mount if they are present on disk, but the forwarded GnuPG agent socket is still accessible.
- `--podman` (opt-in): Forwards the host rootless podman socket. The agent can use this to launch **sibling containers** on the host, which is equivalent to a full sandbox escape (e.g. `podman run -v /:/host ...`).

#### Running Containers: `--podman` vs `--privileged`
If you want the agent to be able to run its own containers, `agent-sandbox` supports two distinct models:

1. **Nested Containers (Safe):** Pass `--privileged` when launching the sandbox. The sandbox image contains its own baked-in Podman stack. `--privileged` gives the sandbox container enough kernel permissions to run a securely isolated Podman daemon *inside* the sandbox. The agent cannot use this to escape to the host.
2. **Sibling Containers (Unsafe):** Pass `--podman` to forward your host's Podman socket into the sandbox. When the agent runs `podman run`, it talks to your host machine's Podman daemon. The container is created on the host alongside the sandbox. This does *not* require `--privileged`, but it allows the agent to control your host's containers and easily escape the sandbox. Use this only when you need the agent to interact with existing host infrastructure or leverage the host's image cache for performance.
