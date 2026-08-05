#!/usr/bin/env bash
# List agent-sandbox containers.

# Appease shellcheck since preamble sets this but we only use IMAGE
: "${AGENT_SANDBOX_NETWORK:?}"

list_all=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--all) list_all=1 ;;
    -h|--help)
      echo "agent-sandbox-list [-a|--all]"
      echo "Lists agent-sandbox containers. Default: current workspace only."
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ "$list_all" == "1" ]]; then
  echo "All agent-sandbox containers:"
  podman ps -a --filter "ancestor=$AGENT_SANDBOX_IMAGE" \
    --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Label \"agent-sandbox.workspace\"}}"
else
  echo "Agent-sandbox containers for $PWD:"
  podman ps --filter "label=agent-sandbox.workspace=$PWD" \
    --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
fi
