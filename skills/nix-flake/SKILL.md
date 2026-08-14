---
name: nix-flake
description: Work with flake.nix and flake.lock as a project's reproducible interface. Trigger when inspecting or editing flakes, devShells, packages, apps, checks, formatters, or Nix project setup.
compatibility: opencode
metadata:
  workflow: project-interface
  audience: developers-and-agents
---

# Flake Projects

Treat `flake.nix` as the project's API, not merely an installation script. Inspect `flake.nix`, `flake.lock`, README files, and project instructions before inventing setup commands.

## Important outputs

- `packages.<system>.<name>` builds a package or artifact.
- `apps.<system>.<name>` exposes an executable application.
- `devShells.<system>.<name>` defines a development environment.
- `checks.<system>.<name>` validates the project.
- `formatter.<system>` defines the project's Nix formatter.

Use `nix flake show` to inspect available outputs. For the default development shell, use:

```sh
nix develop
nix develop --command <command> [args...]
```

The non-interactive form is preferred for agent work because it runs one command in the declared environment and returns its status.

## Editing a flake

Make the smallest change that matches the flake's existing style and system structure. Reuse existing inputs and package definitions instead of adding duplicate dependencies. Keep platform-specific output conventions intact.

When adding a development tool, prefer the existing `devShells` definition. When adding a project artifact, use the existing `packages` or `apps` structure. Do not replace a `devenv.nix`-managed environment with a hand-written shell unless the project explicitly asks for that change.

After editing, run the project's formatter and checks:

```sh
nix fmt
nix flake check
nix build .#<output>
```

Only update `flake.lock` when input changes are part of the task. Review lockfile changes rather than accepting unrelated upgrades.

## Trust and reproducibility

Pinned inputs improve reproducibility but do not make their code automatically trustworthy. Treat new inputs, overlays, fetchers, and build hooks as code to review. Prefer the repository's locked inputs and avoid global package installation when the flake already declares the required environment.
