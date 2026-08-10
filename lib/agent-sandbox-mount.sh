#!/usr/bin/env bash
# Bind-mount a host directory into a running sandbox.

: "${AGENT_SANDBOX_NETWORK:?}"  # keep shellcheck quiet about the unused variable from preamble

usage() {
  cat <<'USAGE'
agent-sandbox-ctl mount [SANDBOX] HOST_PATH CONTAINER_PATH

Mount a directory from the host into a running sandbox.
If the sandbox was started with --selinux, the host directory will be
relabeled appropriately.
USAGE
}

[[ $# -gt 0 ]] || { usage; exit 1; }

sandbox_name=""
positional=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox-mount: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    -*)          echo "agent-sandbox-mount: unknown flag '$1'" >&2; exit 1 ;;
    *)           positional+=("$1") ;;
  esac
  shift
done

if [[ ${#positional[@]} -eq 3 ]]; then
  if [[ -n "$sandbox_name" ]]; then
     echo "agent-sandbox-mount: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
  fi
  sandbox_name="${positional[0]}"
  host_path="${positional[1]}"
  container_path="${positional[2]}"
elif [[ ${#positional[@]} -eq 2 ]]; then
  host_path="${positional[0]}"
  container_path="${positional[1]}"
else
  echo "agent-sandbox-mount: expected [SANDBOX] HOST_PATH CONTAINER_PATH" >&2
  usage >&2
  exit 1
fi

if [[ ! -d "$host_path" ]]; then
  echo "agent-sandbox-mount: host path '$host_path' does not exist or is not a directory" >&2
  exit 1
fi
# Resolve absolute path for nsenter
host_path="$(readlink -f "$host_path")"

sandbox="$(resolve_sandbox "$sandbox_name" --running)"
pid="$(podman inspect --format '{{.State.Pid}}' "$sandbox")"

# Check if SELinux relabeling is implied by existing mounts (i.e., started with --selinux)
has_selinux="$(podman inspect --format '{{range .Mounts}}{{.Mode}} {{end}}' "$sandbox" | grep -qw 'z' && echo 1 || echo 0)"

if [[ "$has_selinux" == "1" ]]; then
  # Use podman's native relabeling instead of guessing chcon commands
  podman run --rm --entrypoint /bin/true -v "$host_path:/tmp/relabel:z" "$AGENT_SANDBOX_IMAGE" >/dev/null 2>&1 || true
fi

# Ensure target exists in the sandbox
podman exec "$sandbox" mkdir -p "$container_path"

# Inject the mount
podman unshare nsenter -t "$pid" -m mount --bind "$host_path" "$container_path"

echo "Mounted $host_path to $sandbox:$container_path"
