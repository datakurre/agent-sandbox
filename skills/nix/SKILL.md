---
name: nix
description: Use Nix for reproducible one-off tools and temporary environments. Trigger for nix commands, missing CLI tools, Nix package lookup, or requests to avoid global installation.
compatibility: opencode
metadata:
  workflow: ephemeral-tooling
  audience: developers-and-agents
---

# Nix Tooling

Use the smallest Nix boundary that solves the task.

## Choose the command

- Use `nix run nixpkgs#<package> -- <args>` for one executable needed for one command.
- Use `nix shell nixpkgs#<package> ...` when several packages are needed for a short sequence of commands.
- Use `nix develop --command <command> [args...]` when the current repository provides a flake development shell. See the `nix-flake` skill.

Examples:

```sh
nix run nixpkgs#jq -- --version
nix run nixpkgs#ripgrep -- --glob '*.rs' TODO
nix shell nixpkgs#git nixpkgs#jq
nix develop --command cargo test
```

Do not globally install a tool when Nix or the project's declared environment can provide it. Inspect the repository and its documentation first; an existing project command takes precedence over a guessed package command.

## Nix references

Use `nix search nixpkgs <term>` or inspect a package with `nix eval` before guessing an attribute name. Use explicit flake references and the `--` separator when passing arguments to the executed program.

Remote flakes can execute arbitrary code. Before using an unfamiliar `github:` or URL flake, consider its provenance, lock revision, requested permissions, and whether the project actually needs it.

## Validate changes

For changes to Nix expressions, prefer the project's formatter and checks. Common commands are:

```sh
nix fmt
nix flake check
nix build .#<output>
```

Preserve the existing `flake.lock` unless updating inputs is intentional and requested.
