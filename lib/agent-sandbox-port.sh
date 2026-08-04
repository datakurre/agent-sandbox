#!/usr/bin/env bash
# Publish a port from a *running* sandbox.
#
# Podman cannot add a binding to a container that is already running, and
# --network=container:<id> explicitly forbids port bindings, so there is no
# way to retrofit -p onto a live sandbox.  What does work is a sidecar: a
# second container that publishes the port itself and proxies over a shared
# network to the sandbox, addressed by container name.
#
#   host:8000  ->  sidecar (socat)  ->  sandbox:8000
#
# The sandbox therefore has to be on the shared network.  Rootless podman's
# default netns (pasta/slirp4netns) cannot be joined to one after the fact,
# which is why `agent-sandbox --ports-dynamic` exists: it puts the sandbox on
# the shared network from the start.  Connecting afterwards is attempted
# anyway, since it succeeds for sandboxes launched with ports already.

usage() {
  cat <<'USAGE'
agent-sandbox-port ls
agent-sandbox-port add [--sandbox NAME] [HOST:]CONTAINER[/PROTO]
agent-sandbox-port rm  [--sandbox NAME] (HOST | --all)

  ls    show running sandboxes and the ports forwarded into them
  add   start a forwarder for one port
  rm    stop forwarders

With one sandbox running, --sandbox may be omitted.  With several, it is
required unless the current directory matches exactly one sandbox workspace.

The server inside the sandbox must bind 0.0.0.0, not 127.0.0.1: the sidecar
reaches it over the container network, not over the sandbox's loopback.
USAGE
}

sandbox_containers() {
  podman ps --filter "label=agent-sandbox.role=sandbox" --format '{{.Names}}'
}

sandbox_workspace() {
  podman inspect --format '{{index .Config.Labels "agent-sandbox.workspace"}}' "$1" 2>/dev/null || true
}

forwarder_containers() {
  local target="${1:-}"
  if [[ -n "$target" ]]; then
    podman ps --filter "label=agent-sandbox.role=port-forward" \
              --filter "label=agent-sandbox.target=$target" --format '{{.Names}}'
  else
    podman ps --filter "label=agent-sandbox.role=port-forward" --format '{{.Names}}'
  fi
}

# Resolve which sandbox to act on: an explicit --sandbox, the only one
# running, or the one whose workspace is the current directory.
resolve_sandbox() {
  local explicit="$1"
  if [[ -n "$explicit" ]]; then
    if ! podman container exists "$explicit"; then
      echo "agent-sandbox-port: no container named '$explicit'" >&2
      exit 1
    fi
    printf '%s\n' "$explicit"
    return
  fi

  local names=()
  mapfile -t names < <(sandbox_containers)

  if [[ ${#names[@]} -eq 0 ]]; then
    echo "agent-sandbox-port: no running sandboxes." >&2
    exit 1
  fi
  if [[ ${#names[@]} -eq 1 ]]; then
    printf '%s\n' "${names[0]}"
    return
  fi

  local matches=() name
  for name in "${names[@]}"; do
    [[ "$(sandbox_workspace "$name")" == "$PWD" ]] && matches+=("$name")
  done
  if [[ ${#matches[@]} -eq 1 ]]; then
    printf '%s\n' "${matches[0]}"
    return
  fi

  echo "agent-sandbox-port: several sandboxes are running; pass --sandbox NAME:" >&2
  for name in "${names[@]}"; do
    printf '  %s\t%s\n' "$name" "$(sandbox_workspace "$name")" >&2
  done
  exit 1
}

cmd_ls() {
  local names=() name
  mapfile -t names < <(sandbox_containers)

  if [[ ${#names[@]} -eq 0 ]]; then
    echo "No running sandboxes."
    return 0
  fi

  for name in "${names[@]}"; do
    printf '%s\n' "$name"
    printf '  workspace   %s\n' "$(sandbox_workspace "$name")"

    local published line
    published=$(podman port "$name" 2>/dev/null || true)
    if [[ -n "$published" ]]; then
      while IFS= read -r line; do
        printf '  published   %s\n' "$line"
      done <<< "$published"
    fi

    local forwarders=() forwarder
    mapfile -t forwarders < <(forwarder_containers "$name")
    for forwarder in "${forwarders[@]}"; do
      [[ -n "$forwarder" ]] || continue
      printf '  forwarded   %s  (%s)\n' \
        "$(podman port "$forwarder" 2>/dev/null | tr '\n' ' ')" "$forwarder"
    done
  done
}

cmd_add() {
  local sandbox="$1" spec="$2"
  local host container proto=tcp

  if [[ "$spec" == */* ]]; then
    proto="${spec##*/}"
    spec="${spec%/*}"
  fi
  if [[ "$spec" == *:* ]]; then
    host="${spec%%:*}"
    container="${spec##*:}"
  else
    host="$spec"
    container="$spec"
  fi

  if [[ ! "$host" =~ ^[0-9]+$ || ! "$container" =~ ^[0-9]+$ ]]; then
    echo "agent-sandbox-port: expected [HOST:]CONTAINER[/PROTO], got '$2'" >&2
    exit 1
  fi
  if (( host < 1 || host > 65535 || container < 1 || container > 65535 )); then
    echo "agent-sandbox-port: ports must be within 1-65535" >&2
    exit 1
  fi
  if [[ "$proto" != tcp && "$proto" != udp ]]; then
    echo "agent-sandbox-port: protocol must be tcp or udp" >&2
    exit 1
  fi

  if ! podman network exists "$AGENT_SANDBOX_NETWORK" 2>/dev/null; then
    podman network create "$AGENT_SANDBOX_NETWORK" >/dev/null
  fi

  # Best effort: succeeds when the sandbox is already on a bridge network,
  # fails for the rootless default netns.  The error names the fix.
  if ! podman inspect --format '{{json .NetworkSettings.Networks}}' "$sandbox" \
       | grep -q "\"$AGENT_SANDBOX_NETWORK\""; then
    if ! podman network connect "$AGENT_SANDBOX_NETWORK" "$sandbox" 2>/dev/null; then
      echo "agent-sandbox-port: '$sandbox' is not on the $AGENT_SANDBOX_NETWORK network" >&2
      echo "                    and cannot be joined to it while running." >&2
      echo "                    Relaunch it with: agent-sandbox --ports-dynamic" >&2
      exit 1
    fi
  fi

  local listener="TCP-LISTEN" connector="TCP"
  if [[ "$proto" == udp ]]; then
    listener="UDP-LISTEN"
    connector="UDP"
  fi

  local name="agent-sandbox-fwd-${sandbox}-${host}"
  if podman container exists "$name"; then
    echo "agent-sandbox-port: host port $host is already forwarded ($name)" >&2
    exit 1
  fi

  podman run --detach --rm \
    --name "$name" \
    --network "$AGENT_SANDBOX_NETWORK" \
    --publish "127.0.0.1:$host:$container/$proto" \
    --label "agent-sandbox.role=port-forward" \
    --label "agent-sandbox.target=$sandbox" \
    "$AGENT_SANDBOX_IMAGE" \
    socat "$listener:$container,fork,reuseaddr" "$connector:$sandbox:$container" \
    > /dev/null

  echo "127.0.0.1:$host -> $sandbox:$container/$proto"
  echo "(the server inside must bind 0.0.0.0, not 127.0.0.1)"
}

cmd_rm() {
  local sandbox="$1" target="$2"
  local forwarders=() forwarder removed=0
  mapfile -t forwarders < <(forwarder_containers "$sandbox")

  for forwarder in "${forwarders[@]}"; do
    [[ -n "$forwarder" ]] || continue
    if [[ "$target" == "--all" || "$forwarder" == "agent-sandbox-fwd-${sandbox}-${target}" ]]; then
      podman rm -f "$forwarder" > /dev/null
      echo "removed $forwarder"
      removed=$((removed + 1))
    fi
  done

  if [[ "$removed" -eq 0 ]]; then
    echo "agent-sandbox-port: nothing to remove" >&2
    exit 1
  fi
}

# ── Argument parsing ────────────────────────────────────────────────────────

[[ $# -gt 0 ]] || { usage; exit 1; }

action="$1"
shift

sandbox_name=""
positional=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox-port: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    --all)       positional+=("--all") ;;
    -*)          echo "agent-sandbox-port: unknown flag '$1'" >&2; exit 1 ;;
    *)           positional+=("$1") ;;
  esac
  shift
done

case "$action" in
  ls|list)
    cmd_ls
    ;;
  add)
    [[ ${#positional[@]} -eq 1 ]] || { usage; exit 1; }
    cmd_add "$(resolve_sandbox "$sandbox_name")" "${positional[0]}"
    ;;
  rm|remove)
    [[ ${#positional[@]} -eq 1 ]] || { usage; exit 1; }
    cmd_rm "$(resolve_sandbox "$sandbox_name")" "${positional[0]}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    echo "agent-sandbox-port: unknown command '$action'" >&2
    usage >&2
    exit 1
    ;;
esac
