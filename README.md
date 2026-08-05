# agent-sandbox

Sandboxed AI coding environment that runs inside a rootless Podman container.
Launch `opencode` (or any other tool) with SSH agent, GPG signing, Git identity,
host Podman socket, and `devenv` state all wired through automatically.

## Install

### From a local clone

```sh
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#          # installs agent-sandbox, load, and purge scripts
```

### From a remote flake

```sh
nix profile add github:datakurre/agent-sandbox
```

After installing, build the container image (one-time):

```sh
agent-sandbox-load
```

## Usage

```
agent-sandbox [FLAGS] [-- PODMAN_ARGS...] [-- COMMAND...]
```

**With no arguments** `agent-sandbox` launches opencode inside the sandbox with
the current working directory mounted at `/workspace` and every integration
enabled.  If the current directory contains a `devenv.nix`, opencode is started
through a devenv shell (`devenv shell -- opencode .`) so project dependencies
are loaded automatically.

### Override the container command

Everything after the second `--` replaces the default command:

```sh
agent-sandbox -- -- bash                            # interactive shell
agent-sandbox -- -- bash -c "nix build .# && echo done"
agent-sandbox -- -- devenv shell
```

### Pass podman flags

Podman run flags go between two `--` sentinels.  Flags go before the first
`--`, additional podman args between the first and second, and the container
command after the second:

```sh
agent-sandbox -- --privileged                     # enable nested podman
agent-sandbox -- --network=host                   # host network
agent-sandbox -- --privileged -- bash              # podman flag + bash
agent-sandbox --no-workspace -v ~/src:/workspace:rw   # custom workspace mount
```

### Flags

Some integrations are **on by default** while others are opt-in. Enable or disable with the matching flag.

| Flag                    | Default | What it does                                          |
| ----------------------- | ------- | ----------------------------------------------------- |
| `--workspace` / `--no-workspace` | on | mount `$PWD` as `/workspace/<dirname>:rw`              |
| `--selinux` / `--no-selinux`     | off | add SELinux shared relabel (`:z`) to built-in writable mounts |
| `--ssh` / `--no-ssh`             | on | forward `SSH_AUTH_SOCK`                                |
| `--git` / `--no-git`             | on | mount `~/.gitconfig`, forward `user.name`/`user.email` |
| `--gpg-agent` / `--no-gpg-agent` | on | forward host gpg-agent socket for commit signing       |
| `--gpg-sign` / `--no-gpg-sign`   | on | enable/disable git commit signing inside container     |
| `--opencode` / `--no-opencode`   | on | mount opencode config, cache, and data dirs            |
| `--claude-code` / `--no-claude-code` | off | mount claude configuration files; use `claude` as default command |
| `--copilot` / `--no-copilot`     | off | mount github-copilot-cli config dir; use `copilot` as default command |
| `--antigravity` / `--no-antigravity` | off | mount antigravity-cli config, cache, and data dirs; use `agy` as default command |
| `--devenv` / `--no-devenv`       | on | mount `~/.local/share/devenv` across sessions          |
| `--podman` / `--no-podman`       | off | forward host rootless podman socket (sibling containers) |
| `--nix` / `--no-nix`             | on | mount host `/nix/store` to delegate builds to host daemon |
| `--gnupg-private` / `--no-gnupg-private` | off | expose `~/.gnupg` even when it holds on-disk secret keys |
| `--firewall` / `--no-firewall`   | off | route container traffic through a domain-filtering proxy |
| `--meter-network` / `--no-meter-network` | off | capture network traffic for a post-run summary           |

You can also pass `-v` / `-v*` volume mounts before `--`.  Relative paths in
the source are resolved against `$PWD`; relative destinations are prefixed with
`/workspace/`.

By default, built-in writable binds stay plain `:rw` so non-SELinux hosts see
no relabel side-effects.  On SELinux hosts, pass `--selinux` to apply shared
relabeling (`:z`) to built-in writable binds.  User-provided `-v` options are
preserved exactly as supplied.

### Examples

```sh
agent-sandbox                                    # opencode, everything on
agent-sandbox --no-ssh                           # drop an integration
agent-sandbox --copilot                          # github-copilot-cli (copilot), everything on
agent-sandbox --antigravity                      # antigravity-cli (agy), everything on
agent-sandbox --no-workspace                     # no CWD mount
agent-sandbox --selinux                          # enable :z on built-in writable binds
agent-sandbox -- -- bash                           # interactive bash with all integrations
agent-sandbox -- -- devenv shell                   # devenv shell with opencode config mounted
agent-sandbox -- --privileged                      # nested podman inside container
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

1. `agent-sandbox-load` imports the OCI image (built with `pkgs.dockerTools.streamLayeredImage`) into the host's podman image store.
2. `agent-sandbox` calls `podman run` with `--userns=keep-id`, tmpfs mounts for ephemeral home subdirectories, explicit bind mounts for persistent state (opencode, devenv, …), and forwarded sockets (ssh, gpg, podman).
3. A slim entrypoint loads the Nix store registration so `nix` commands work from the start, sets up the gpg-agent symlink when requested, then `exec`s the container command.

## Trust model

By design, `agent-sandbox` includes options that pierce the sandbox boundary. Note that these give any agent running inside the container capabilities on the host:
- `--ssh` (on by default): The agent can authenticate as you using your forwarded SSH identity (e.g. `git push` to your repos).
- `--gpg-agent` (on by default): The agent can sign commits or authenticate with any key held by your host GnuPG agent. Note that `agent-sandbox` protects your private key files by checking for them and gracefully failing the GNUPG directory mount if they are present on disk, but the forwarded GnuPG agent socket is still accessible.
- `--podman` (opt-in): Forwards the host rootless podman socket. The agent can use this to launch new containers on the host, which is equivalent to a full escape (e.g. `podman run -v /:/host ...`).
