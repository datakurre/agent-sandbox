#!/usr/bin/env bash
# List agent-sandbox containers.
#
# Selection is by role label, not by `ancestor=`: the sidecar and the socat port
# forwarders run from the same image as the sandbox, so filtering on the image
# reported infrastructure containers as sandboxes (with an empty workspace
# column).  Labels also survive `agent-sandbox-ctl load` reassigning the tag to a
# rebuilt image, which leaves already-running containers matching no ancestor.

usage() {
  cat <<'USAGE'
agent-sandbox-list [-a|--all] [--roles]

  (default)    running sandboxes for the current workspace
  -a, --all    every sandbox, any workspace, including stopped ones
  --roles      also list the proxy sidecars and port forwarders

The PROXY column is the launch mode: firewall, meter, or off.
USAGE
}

list_all=0
show_roles=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--all)  list_all=1 ;;
    --roles)   show_roles=1 ;;
    -h|--help) usage; exit 0 ;;
    -*)        echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

sandbox_format='table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Label "agent-sandbox.proxy"}}\t{{.Label "agent-sandbox.workspace"}}'

if [[ "$list_all" == "1" ]]; then
  echo "All agent-sandbox containers:"
  podman ps -a --filter "label=agent-sandbox.role=sandbox" --format "$sandbox_format"
else
  echo "Agent-sandbox containers for $PWD:"
  podman ps --filter "label=agent-sandbox.role=sandbox" \
            --filter "label=agent-sandbox.workspace=$PWD" --format "$sandbox_format"
fi

if [[ "$show_roles" == "1" ]]; then
  role_format='table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Label "agent-sandbox.target"}}'
  ps_args=()
  [[ "$list_all" == "1" ]] && ps_args+=(-a)

  echo
  echo "Proxy sidecars:"
  podman ps "${ps_args[@]}" --filter "label=agent-sandbox.role=proxy" --format "$role_format"

  echo
  echo "Port forwarders:"
  podman ps "${ps_args[@]}" --filter "label=agent-sandbox.role=port-forward" --format "$role_format"
fi
