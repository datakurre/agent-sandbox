#!/usr/bin/env bash
# Bind-mount a host directory into a running sandbox.

: "${AGENT_SANDBOX_NETWORK:?}"  # keep shellcheck quiet about the unused variable from preamble

usage() {
  cat <<'USAGE'
agent-sandbox-ctl mount [SANDBOX] HOST_PATH CONTAINER_PATH
agent-sandbox-ctl mount export [SANDBOX] [--sandbox NAME]

Mount a directory from the host into a running sandbox.
If the sandbox was started with --selinux, the host directory will be
relabeled appropriately.

export prints the [mounts] section of a running sandbox as AGENTS.md TOML,
omitting the built-in mounts every sandbox gets (workspace, dotfiles, nix, ...).
USAGE
}

[[ $# -gt 0 ]] || { usage; exit 1; }

if [[ "$1" == "export" ]]; then
  shift
  sandbox_name=""
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
      *)
        if [[ -z "$sandbox_name" ]]; then
          sandbox_name="$1"
        else
          echo "agent-sandbox-mount: export takes at most one argument (the sandbox)" >&2; exit 1
        fi
        ;;
    esac
    shift
  done

  sandbox="$(resolve_sandbox "$sandbox_name" --running)"
  workspace_dir=$(sandbox_workspace "$sandbox")

  # The same destinations every launch mounts in (workspace, dotfiles, nix,
  # the sidecar directories) are excluded here, the same way status omits the
  # baseline deny_ips from a `proxy export`: they are not something AGENTS.md
  # declared, so round-tripping them into a new config would be redundant.
  mounts_toml=$(podman inspect --format '{{json .Mounts}}' "$sandbox" 2>/dev/null | jq -r --arg ws "$workspace_dir" '
    .[] | select(.Type == "bind") |
    select(.Destination != "/workspace") |
    select(.Destination != "/home/user/.local/share/devenv") |
    select(.Destination | test("^/home/user/.(local|config|cache)/") | not) |
    select(.Destination | test("^/home/user/.(gitconfig|gnupg|ssh)") | not) |
    select(.Destination | test("^/run/") | not) |
    select(.Destination | test("^/sidecar_") | not) |
    select(.Destination | test("^/nix") | not) |
    select(.Destination | test("^/etc/") | not) |
    .Source as $src | .Destination as $dst | .Options as $opts |
    (
      if ($src | startswith($ws + "/")) then
        "." + ($src | ltrimstr($ws))
      elif ($src == $ws) then
        "."
      else
        $src
      end
    ) as $rel_src |
    (
      if ($opts | index("ro")) then
        "\"" + $rel_src + "\" = { destination = \"" + $dst + "\", options = \"ro\" }"
      elif ($opts | index("z")) then
        "\"" + $rel_src + "\" = { destination = \"" + $dst + "\", options = \"z\" }"
      else
        "\"" + $rel_src + "\" = \"" + $dst + "\""
      end
    )
  ' || true)

  if [[ -n "$mounts_toml" ]]; then
    echo '```toml agent-sandbox'
    echo "[mounts]"
    echo "$mounts_toml"
    echo '```'
  fi
  exit 0
fi

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

# Before the relabel below, which would otherwise start a throwaway container
# for nothing.  This refusal matters more than attach's: the nsenter --bind at
# the end of this script *succeeds* against a microVM and changes nothing the
# guest can see, so without the guard the command would report success and do
# nothing at all.
refuse_if_krun "$sandbox" "mount" \
  "A host-side bind lands in the VMM's mount namespace, not in the guest, so it" \
  "would appear to succeed and have no effect.  virtio-fs cannot take a new" \
  "share after boot.  Relaunch with the mount in place:  agent-sandbox --krun -v ..."

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
