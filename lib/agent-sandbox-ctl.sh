#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  echo "Usage: agent-sandbox-ctl <command> [args...]"
  echo "Commands:"
  echo "  load   Load the agent-sandbox image"
  echo "  purge  Purge old agent-sandbox containers"
  echo "  port   Manage port forwarding"
  echo "  list   List active sandboxes"
  exit 1
fi
shift

case "$cmd" in
  load)  exec agent-sandbox-load "$@" ;;
  purge) exec agent-sandbox-purge "$@" ;;
  port)  exec agent-sandbox-port "$@" ;;
  list)  exec agent-sandbox-list "$@" ;;
  *)     echo "agent-sandbox-ctl: unknown command: $cmd" >&2; exit 1 ;;
esac
