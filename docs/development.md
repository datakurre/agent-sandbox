# Development

This page covers how to extend `agent-sandbox`: adding launcher integrations, bundled agents, or image tools.

## How to add a new integration

1. Add a `want_{name}` toggle in `cli/src/bin/agent-sandbox.rs`, after the
   existing toggles.
2. Add `--{name}` / `--no-{name}` arms in the argument parsing loop.
3. Put the mount/env logic in `cli/src/launch.rs` as a function returning the
   `-v`/`-e` fragments, and call it from the launcher next to the other blocks.
   Keeping the logic in `launch.rs` is what makes it unit-testable: flags are
   parsed once and never re-read, which is the pattern the existing fragments follow.
4. If container-side setup is needed in the entrypoint, gate it on an env
   var (e.g. `AGENT_SANDBOX_*`) and pass that var from the launcher.
5. Update `print_usage` and `docs/usage.md`.
6. Test the fragment, and the flag that reaches it: a `#[cfg(test)]` case in
   `launch.rs` for what the fragment produces, and a case in
   `cli/tests/launcher_argv.rs` for the flag actually assembling it into the
   `podman run` command line. Then `make unittest`, which also builds the docs.
7. If the integration depends on a real container — a mount that has to be
   read-only, a port that has to carry traffic, a route the firewall has to
   refuse — add a case under `tests/integration/` too, and run it on the host.

See [Testing](testing.md) for the two tiers, what each one can and cannot
establish, and how to add to either.

## How to add a new agent

Add an entry to `agents.nix`. The entry drives:

- inclusion of the agent package in the image PATH,
- accepted agent names in the launcher,
- command dispatch when selecting that agent,
- persisted home-state mounts (`state` directories, `stateFiles` files),
- how each launcher flag that reaches the agent is spelled for it
  (`modelArg`, `sessionArg`, `forkArg`, `providerArg`, `creditLimitArg`),
- the arguments that make it read a prompt from stdin (`programmaticArgs`).

Two rules for the flag mappings, both there because the alternative is silent
misbehaviour rather than an error:

- **Omit the key when the agent has no such flag.** The launcher then refuses
  `--session`/`--fork`/… for that agent. Do not invent a spelling: several
  agents accept an unknown-looking argument as a *prompt* rather than
  rejecting it.
- **Read the mapping off the agent's own `--help`, for the version pinned in
  the flake.** These drift. `copilot` dropped `--max-ai-credits`; `codex` has
  no `-p/--print` at all, and its `-p` means `--profile`.

The user's value replaces a `{}` token in the mapping, or is appended when
there is none — `forkArg = [ "--resume" "{}" "--fork-session" ]` is how an
agent that spells a fork as a qualified resume is expressed.

The file's shape is checked at build time against `agents-schema.json`
(`make -C tests/unit schema`, or the `agents-schema` flake check): required
keys, no unknown keys (so a typo cannot default silently to "unsupported"),
non-empty mappings, at most one `{}` per mapping, and `state`/`stateFiles`
paths that stay under `$HOME`. Update the schema together with the field it
describes.

Downstream flakes can override the catalog and default agent via:

`(import ./default.nix { inherit pkgs lib; }).override { agents = ...; defaultAgent = "..."; }`

## How to add a new tool to the image

Add the package to `baseTools`.  It is automatically included in the PATH
and Nix store registration.  No other changes needed.

## Important implementation constraints

- The launcher, entrypoint, sidecar and proxy are Rust (`cli/`, `proxy/`); the
  remaining Nix shell wrappers exist only to put the binaries on `PATH` with the
  image reference in the environment. Those wrappers are written with
  `writeShellScriptBin`, where the `''`-quoted bodies are Nix's
  double-single-quote string mechanism.
- The container runs with `--userns=keep-id`, so the uid/gid inside the
  container match the host user.  Passwd/group files are synthesized per-run.
- Tmpfs mounts on `~/.config`, `~/.cache`, `~/.local` provide writable home
  subdirectories by default; persistent tool data (opencode, devenv, …) is
  layered on top via explicit `-v` bind mounts.
- Nested rootless podman inside the container requires `--privileged`.
  The image ships a full podman stack and `/etc/containers` config, so nested
  podman works out of the box when the privilege flag is passed.
- **Host Nix shadowing**: When `--nix` is passed (off by default, but commonly baked in by a `wrapProgram` wrapper), the host `/nix/store` is mounted over the image's own store. Every PATH entry and the entrypoint itself then resolves against the host store rather than the baked-in one. This means the image is not entirely self-contained by default: transferring it to another host, or running garbage collection on a host where it wasn't installed via `nix profile`, may break the container at execution time.
