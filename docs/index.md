# agent-sandbox

**Sandboxed AI coding environment** built on rootless Podman and Nix. Run AI coding agents — `opencode`, `claude`, `copilot`, `codex`, `antigravity`, `pi`, or any bundled tool — in an isolated container. All host integrations are **disabled by default**; you opt in only to what you need.

## What it provides

- **Isolated container** — the agent runs in a minimal Nix-built image with no access to your host filesystem unless you pass `--workspace`.
- **Deny-by-default network firewall** — `--proxy` puts the sandbox behind an HTTP proxy that enforces declarative `[network]` rules from your project's `AGENTS.md` and optional bare-TOML `--config` files. No rules means no outbound traffic.
- **Secrets injection** — `--secrets` resolves credentials with `secretspec` and injects them as HTTP headers, scoped to the exact route you authorize. Secrets never enter the sandbox environment.
- **SSH / GPG forwarding** — `--ssh` and `--gpg` forward host agent sockets; under `--proxy` they travel through a relay that keeps the firewall intact.
- **Cooperative browser** — `agent-sandbox browser` starts a throwaway Chromium on your host behind an allow list of its own, defaulting to the ports your sandbox publishes and nothing else, so an agent can drive a visible browser over CDP without that being an unpoliced hole.
- **Management CLI** — `agent-sandbox ctl` manages running sandboxes: inspect traffic, update policies live, attach a shell, and clean up leftovers.
- **Built-in skills** — every agent gets `agent-sandbox`, `nix`, `nix-flake`, `devenv`, `browser`, `mailpit`, and `commit` skills baked into the image, so it already knows how the sandbox, proxy policy, cooperative browser, local agent mailbox, and required commit trailer work.

## Prerequisites

- **Nix** with [flakes enabled](https://nixos.wiki/wiki/Flakes)
- **Rootless Podman** on the host

## Installation

```sh
# Install from a local clone
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#

# Or install directly (no clone needed)
nix profile add github:datakurre/agent-sandbox
```

Build the container image once after installation:

```sh
agent-sandbox ctl load
```

## Quick start

```sh
# Interactive shell — every agent binary is on PATH, nothing else is exposed
agent-sandbox

# Mount your project and launch opencode
agent-sandbox --workspace opencode

# Add a network firewall enforced by this project's AGENTS.md [network] block
agent-sandbox --workspace --proxy opencode

# Merge a reusable host-owned policy with AGENTS.md (--policy requires --proxy)
agent-sandbox --workspace --proxy --policy development opencode

# Reattach to a running sandbox
agent-sandbox ctl attach

# Publish a port declared in AGENTS.md's [ports] block
agent-sandbox --workspace --ports opencode

# Use standalone TOML config, including project environment defaults
agent-sandbox --workspace --config sandbox.toml --proxy opencode

# Ignore AGENTS.md config while keeping explicitly selected config files
agent-sandbox --workspace --no-agents-md --config sandbox.toml opencode

# Mount extra paths from [mounts], and persist this agent's state across runs
agent-sandbox --workspace --mounts --agent-mounts opencode

# Drive a visible, allow-listed browser from inside the sandbox
agent-sandbox browser &
agent-sandbox --workspace --browser -- claude
```

## Choosing your launch flags

| Goal | Flags to add |
|------|-------------|
| Expose current directory at `/workspace/<name>` | `--workspace` |
| Launch a specific agent | `agent-sandbox <agent>` (`opencode`, `claude`, `copilot`, `codex`, `antigravity`, `pi`) |
| Reattach to a sandbox already running | `agent-sandbox ctl attach` |
| Publish a declared port | `--ports` + `[ports]` in `AGENTS.md` or a `--config` file |
| Mount extra paths, or persist agent state | `--mounts` + `[mounts]` in `AGENTS.md` or a `--config` file, or `--agent-mounts` |
| Set sandbox environment defaults | `[env]` in `AGENTS.md` or a `--config` file |
| Ignore the workspace `AGENTS.md` for launcher config | `--no-agents-md` (explicit `--config` files remain active) |
| Allow specific outbound network traffic | `--proxy` + `[network]` in `AGENTS.md` or a `--config` file |
| Merge a reusable host-owned network policy | `--proxy --policy NAME` |
| Forward SSH keys (e.g. for `git push`) | `--ssh` |
| Forward GPG agent (e.g. for signed commits) | `--gpg` |
| Run nested containers inside the sandbox | `--privileged` |
| Add a hardware VM boundary | `--krun` (requires `/dev/kvm`) |
| Inject API credentials scoped to a route | `--secrets` + `--proxy` |
| Let the agent drive a visible browser you can watch | run `agent-sandbox browser`, then relaunch with `--browser` |

See [Usage & Flags](usage.md) for the complete flags reference, [Configuration](configuration.md) for `AGENTS.md`, `--config`, and `[env]` syntax, [Cooperative Browser](browser.md) for multi-user browser sessions, and [Trust Model](trust-model.md) for the security implications of each flag.
