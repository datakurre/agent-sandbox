# agent-sandbox

Sandboxed AI coding environment that runs inside a rootless Podman container.
Launch `opencode` (or any other tool) and explicitly opt-in to integrations. By default, the environment is isolated and secure.

## Quick start

```sh
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#          # installs agent-sandbox
```

Or without cloning:

```sh
nix profile add github:datakurre/agent-sandbox
```

Either way, build the container image once before first use:

```sh
agent-sandbox ctl load
```

Then launch a tool. For a secure, basic coding session, you typically want to mount your current directory (`--workspace`) and optionally control network access (`--proxy`):

```sh
# Launch opencode with just the current directory mounted at /workspace
agent-sandbox --workspace opencode

# Launch opencode with the current directory and a network proxy firewall
agent-sandbox --workspace --proxy opencode
```

Advanced features like SSH forwarding (`--ssh`), GPG signing (`--gpg`), host Podman socket forwarding (`--podman`), and `devenv` integration are available but opt-in. See [Usage](usage.md) for overriding the container command, passing raw podman flags, and the full flags reference.
