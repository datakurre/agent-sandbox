# AGENTS.md – agent-sandbox

## Project overview

`agent-sandbox` is a Nix flake that produces a rootless Podman container image
("agent-sandbox") together with a launcher binary (`agent-sandbox`) and a
loader binary (`agent-sandbox-load`).

- **default.nix** – single Nix module; builds the image and the two scripts.
- **flake.nix**  – flake entry point; exposes `packages.<system>.default` and
  `apps.<system>.default`.

## Architecture

### Image (`image` attr in `default.nix`)

Built with `pkgs.dockerTools.buildImage`.  All tools are baked into a
`buildEnv` and registered in the Nix store database so `nix` / `devenv` / Nix
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

### Entrypoint (`safepilot-entrypoint`)

1. Loads the Nix store registration on first start.
2. When `AGENT_SANDBOX_GPG_AGENT=1`, symlinks the forwarded host gpg-agent
   socket into `~/.gnupg/S.gpg-agent`.
3. `exec "$@"`.

### Launcher (`agent-sandbox`)

A bash script that wraps `podman run`.  Call flow:

1. Parse flags: consume known flags (`--ssh`, `--no-git`, `--no-workspace`,
   etc.), pass through `-v` volume mounts (with relative-path expansion),
   stop at `--` sentinel.
2. Build mounts array from toggles (ssh socket, git config, gpg socket,
   opencode dirs, devenv dir, podman host socket, CWD workspace).
3. Build env_args array from toggles (SSH_AUTH_SOCK, git identity,
   CONTAINER_HOST, DOCKER_HOST, TERM, COLORTERM).
4. Create ephemeral `/etc/passwd` and `/etc/group` with the host user's uid/gid.
5. Call `podman run` with `--userns=keep-id`, tmpfs for `~/.config`,
   `~/.cache`, `~/.local`, all mounts and env vars, then the image and the
   final command (default `opencode`, overridable via `-- …`).

### Loader (`agent-sandbox-load`)

`podman load < ${image}`

## How to add a new integration

1. Add a `want_{name}=1` toggle after the existing toggles (line ~280).
2. Add `--{name}` / `--no-{name}` cases in the `while` loop (line ~290).
3. Add the mount/env logic after the existing blocks (after `
   want_podman`).
4. If container-side setup is needed in the entrypoint, gate it on an env
   var (e.g. `AGENT_SANDBOX_*`) and pass that var from the launcher.
5. Update the usage comment.
6. Test: `nix flake check --no-build`

## How to add a new tool to the image

Add the package to `baseTools`.  It is automatically included in the PATH
and Nix store registration.  No other changes needed.

## Important implementation constraints

- Nix shell scripts are written with `writeShellScriptBin`; the `''` escaping
  inheredoc-style strings is Nix's double-single-quote mechanism.
- The container runs with `--userns=keep-id`, so the uid/gid inside the
  container match the host user.  Passwd/group files are synthesized per-run.
- Tmpfs mounts on `~/.config`, `~/.cache`, `~/.local` provide writable home
  subdirectories by default; persistent tool data (opencode, devenv, …) is
  layered on top via explicit `-v` bind mounts.
- Nested rootless podman inside the container requires `--privileged`.
  The image ships a full podman stack and `/etc/containers` config, so nested
  podman works out of the box when the privilege flag is passed.
