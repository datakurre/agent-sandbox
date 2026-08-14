---
name: devenv
description: Use devenv.sh environments defined by devenv.sh or devenv.nix, with flake development shells as fallback. Trigger for devenv, devenv.sh, devenv.nix, environment setup, services, or project commands that need the declared development environment.
compatibility: opencode
metadata:
  workflow: declared-development-environment
  audience: developers-and-agents
---

# devenv Projects

Run project commands inside the environment the project declares. Prefer the non-interactive form:

```sh
devenv shell -- <command> [args...]
```

Examples:

```sh
devenv shell -- cargo test
devenv shell -- npm test
devenv shell -- ./scripts/check.sh
```

## Configuration precedence

Inspect the repository before running commands:

1. If the project has `devenv.sh`, use `devenv shell -- <command>` for every project command. Update `devenv.sh` when the project environment or its exported variables need to change; do not work around it with ad-hoc host installation.
2. Otherwise, if the project has `devenv.nix`, use `devenv shell -- <command>` and update `devenv.nix` for packages, languages, scripts, services, or environment variables.
3. If no devenv configuration exists but `flake.nix` exposes `devShell` or `devShells`, use `nix develop --command <command>` and follow the `nix-flake` skill.
4. If none of these environments exists, use the project's documented commands and use `nix run` for isolated missing tools where appropriate.

Prefer project-defined devenv scripts and service configuration over reconstructing their underlying commands manually. Use plain `devenv shell` only when an interactive shell is specifically needed; agents should normally use `devenv shell -- ...`.

## Environment changes

Make environment changes in the owning configuration file. Keep language versions, packages, scripts, services, and environment variables reproducible. After changes, run the project's checks through the same declared environment and review generated lockfile changes before committing them.
