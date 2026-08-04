#!/usr/bin/env bash
# Remove everything agent-sandbox leaves on the host: port forwarders, the
# sandbox containers themselves, the shared network, and the image.

force=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--force) force=1 ;;
    -h|--help)
      echo "agent-sandbox-purge [-f|--force]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

confirm() {
  [[ "$force" == "1" ]] && return 0
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" =~ ^[Yy] ]]
}

echo "=== agent-sandbox-purge ==="
echo

# ── Port forwarders ───────────────────────────────────────────────────────
# Removed first: they hold the shared network open.
forwarders=$(podman ps -a --filter "label=agent-sandbox.role=port-forward" -q 2>/dev/null || true)
if [[ -n "$forwarders" ]]; then
  echo "Port forwarders:"
  podman ps -a --filter "label=agent-sandbox.role=port-forward" \
    --format "  {{.ID}}  {{.Names}}  {{.Status}}"
  echo
  if confirm "Remove these forwarders?"; then
    xargs -r podman rm -f <<< "$forwarders" > /dev/null
    echo "Forwarders removed."
  else
    echo "Skipped."
  fi
else
  echo "No port forwarders found."
fi
echo

# ── Containers ────────────────────────────────────────────────────────────
# By image rather than by label, so containers created before labelling
# existed are caught too.
containers=$(podman ps -a --filter "ancestor=$AGENT_SANDBOX_IMAGE" -q 2>/dev/null || true)
if [[ -n "$containers" ]]; then
  echo "Agent-sandbox containers:"
  podman ps -a --filter "ancestor=$AGENT_SANDBOX_IMAGE" \
    --format "  {{.ID}}  {{.Names}}  {{.Status}}"
  echo
  if confirm "Remove these containers?"; then
    xargs -r podman rm -f <<< "$containers" > /dev/null
    echo "Containers removed."
  else
    echo "Skipped."
  fi
else
  echo "No agent-sandbox containers found."
fi
echo

# ── Network ───────────────────────────────────────────────────────────────
if podman network exists "$AGENT_SANDBOX_NETWORK" 2>/dev/null; then
  echo "Network: $AGENT_SANDBOX_NETWORK"
  echo
  if confirm "Remove this network?"; then
    podman network rm -f "$AGENT_SANDBOX_NETWORK" > /dev/null
    echo "Network removed."
  else
    echo "Skipped."
  fi
else
  echo "No agent-sandbox network found."
fi
echo

# ── Image ─────────────────────────────────────────────────────────────────
if podman image exists "$AGENT_SANDBOX_IMAGE" 2>/dev/null; then
  echo "Image: $AGENT_SANDBOX_IMAGE"
  echo
  if confirm "Remove this image?"; then
    podman rmi -f "$AGENT_SANDBOX_IMAGE"
    echo "Image removed."
  else
    echo "Skipped."
  fi
else
  echo "No agent-sandbox image found."
fi

echo
echo "Done."
