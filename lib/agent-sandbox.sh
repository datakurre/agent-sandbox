#!/usr/bin/env bash
# agent-sandbox launcher.  Wraps `podman run` with the host integrations the
# sandboxed agent needs, and nothing else.
#
# The Nix wrapper prepends definitions for AGENT_SANDBOX_IMAGE and
# AGENT_SANDBOX_NETWORK, and puts podman, git, and the agent-sandbox-* helpers
# on PATH.  Commands *inside* the container are named bare (opencode, claude,
# …) and resolve through the image's own PATH.



if ! podman image exists "$AGENT_SANDBOX_IMAGE" 2>/dev/null; then
  echo "agent-sandbox: image $AGENT_SANDBOX_IMAGE not found. Run 'agent-sandbox-ctl load' first." >&2
  exit 1
fi

# ── Defaults ────────────────────────────────────────────────────────────────
# On by default: things the agent needs to be useful in a normal git workflow.
# Off by default: things that widen the sandbox boundary (podman socket,
# on-disk gpg secrets) or that only some hosts want (selinux relabelling).
want_ssh=0
want_git=0
want_gpg=0
want_gpg_sign=0
want_gnupg_private=0
want_devenv=0
want_nix=0
want_podman=0
want_workspace=0
want_selinux=0
want_ports=0
want_ports_dynamic=0
want_ports_any_interface=0
want_firewall=0
want_meter_network=0

agent=""
want_help=0

if [[ -z "${AGENT_SANDBOX_AGENT_SPECS:-}" ]]; then
  AGENT_SANDBOX_AGENT_SPECS=$'opencode\t["opencode","."]\t[".local/share/opencode",".config/opencode",".cache/opencode"]\t[]\nclaude-code\t["claude"]\t[".claude"]\t[".claude.json"]\ncopilot\t["copilot"]\t[".copilot"]\t[]\nantigravity\t["agy","."]\t[".local/share/antigravity-cli",".config/antigravity-cli",".cache/antigravity-cli",".gemini"]\t[]'
fi

declare -a agent_names=()
declare -A agent_cmd_json=()
declare -A agent_state_json=()
declare -A agent_state_files_json=()

while IFS=$'\t' read -r name cmd_json state_json state_files_json; do
  [[ -n "$name" ]] || continue
  agent_names+=("$name")
  agent_cmd_json["$name"]="$cmd_json"
  agent_state_json["$name"]="$state_json"
  agent_state_files_json["$name"]="$state_files_json"
done <<< "${AGENT_SANDBOX_AGENT_SPECS}"

agent_list="${agent_names[*]}"

if [[ $# -eq 0 ]]; then
  want_help=1
fi

usage() {
  cat <<USAGE
agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]

Runs an AI coding agent inside a rootless podman container.
Use flags to opt-in to integrations like mounting the current directory,
forwarding SSH, or exposing Git identity.

  agent-sandbox                      prints this help
  agent-sandbox opencode             launch opencode with its specific mounts
  agent-sandbox --podman opencode    launch opencode with podman enabled
  agent-sandbox opencode -- bash     launch bash with opencode mounts
  agent-sandbox -- bash              launch bash without agent specific mounts
  agent-sandbox --privileged opencode
                                     pass --privileged to podman run

Agents:
  ${agent_list}

Integrations (use --X to enable, --no-X to disable):
  --workspace       $([[ "$want_workspace" == "1" ]] && echo "[on ]" || echo "[off]") Mounts the host's current working directory into /workspace/<dirname>.
  --ssh             $([[ "$want_ssh" == "1" ]] && echo "[on ]" || echo "[off]") Forwards the host's SSH_AUTH_SOCK to the container.
  --git             $([[ "$want_git" == "1" ]] && echo "[on ]" || echo "[off]") Mounts host Git configurations and passes identity env vars.
  --gpg-agent       $([[ "$want_gpg" == "1" ]] && echo "[on ]" || echo "[off]") Forwards the host GnuPG agent socket for commit signing.
  --gpg-sign        $([[ "$want_gpg_sign" == "1" ]] && echo "[on ]" || echo "[off]") Sets git config to enable commit signing inside the container.
  --gnupg-private   $([[ "$want_gnupg_private" == "1" ]] && echo "[on ]" || echo "[off]") Exposes ~/.gnupg even if it holds on-disk secret keys.
  --devenv          $([[ "$want_devenv" == "1" ]] && echo "[on ]" || echo "[off]") Persists ~/.local/share/devenv across sessions.
  --nix             $([[ "$want_nix" == "1" ]] && echo "[on ]" || echo "[off]") Mounts the host /nix/store for native Nix execution.
  --podman          $([[ "$want_podman" == "1" ]] && echo "[on ]" || echo "[off]") Forwards the host rootless Podman socket (sibling containers).
  --selinux         $([[ "$want_selinux" == "1" ]] && echo "[on ]" || echo "[off]") Applies SELinux shared relabeling (:z) to writable binds.
  --firewall        $([[ "$want_firewall" == "1" ]] && echo "[on ]" || echo "[off]") Routes HTTP(S) traffic through a domain-filtering proxy (blocks direct internet access).
  --meter-network   $([[ "$want_meter_network" == "1" ]] && echo "[on ]" || echo "[off]") Routes HTTP(S) traffic through a proxy to capture a post-run summary (blocks direct internet access).
                         Either flag also enables 'agent-sandbox-ctl net' for the running sandbox.

Ports:
  --port [HOST:]CONTAINER[/PROTO]          Publish a port, repeatable.
  --ports / --no-ports               $([[ "$want_ports" == "1" ]] && echo "[on ]" || echo "[off]") Honors [ports] declarations from AGENTS.md.
  --ports-dynamic                          Allows \`agent-sandbox-ctl port add\` post-launch.
  --ports-any-interface                    Permits port binds outside of loopback interfaces.

Mounts:
  -v SOURCE[:DEST[:OPTS]]   relative SOURCE resolves against \$PWD; relative
                            DEST is placed under /workspace; "." means
                            /workspace itself

Podman / Environment:
  --privileged              pass --privileged to podman run (for nested podman)
  -e, --env NAME=VAL        pass environment variable to podman
  --podman-args             treat all following args (until --) as podman args

--podman, --ssh and --gpg-agent each hand the agent a capability that reaches
outside the sandbox. --podman forwards the host podman socket, allowing the 
agent to create sibling containers on the host (a full sandbox escape).
To safely let the agent run containers, use --privileged instead to enable 
securely nested containers inside the sandbox. See README for details.
USAGE
}

mounts=()
env_args=()
podman_args=()
cmd_args=()
port_specs=()

# ── Helpers ─────────────────────────────────────────────────────────────────

# Expand a -v spec.  Relative sources resolve against $PWD; relative
# destinations land under /workspace.  A spec with no destination mounts at
# the same path it came from, rather than emitting a trailing colon.
expand_v() {
  local spec="$1" src dest opts
  IFS=':' read -r src dest opts <<< "$spec"
  src="${src/#\~/$HOME}"
  [[ "$src" == "." ]] && src="$PWD"
  [[ "$src" != /* ]] && src="$PWD/$src"
  if [[ -z "$dest" ]]; then
    dest="$src"
  elif [[ "$dest" != /* ]]; then
    [[ "$dest" == "." ]] && dest="/workspace" || dest="/workspace/$dest"
  fi
  printf '%s\n' "$src:$dest${opts:+:$opts}"
}

# Bind a host path read-write, creating it first.  Used for every persistent
# tool-state directory, which is why they all pick up $rw_mount_opts together.
mount_rw() {
  local host="$1" container="$2"
  mkdir -p "$host"
  mounts+=("-v" "$host:$container:$rw_mount_opts")
}

# Validate a --port spec and normalise it to bind:host:container/proto.
parse_port_spec() {
  local spec="$1" host container proto=tcp
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
    echo "agent-sandbox: --port '$1': expected [HOST:]CONTAINER[/PROTO]" >&2
    exit 1
  fi
  if (( host < 1 || host > 65535 || container < 1 || container > 65535 )); then
    echo "agent-sandbox: --port '$1': ports must be within 1-65535" >&2
    exit 1
  fi
  if [[ "$proto" != tcp && "$proto" != udp ]]; then
    echo "agent-sandbox: --port '$1': protocol must be tcp or udp" >&2
    exit 1
  fi
  printf '%s\n' "$bind_address:$host:$container/$proto"
}

# ── Flag parsing ────────────────────────────────────────────────────────────
# Phase 1: agent-sandbox flags and podman options. The first -- ends it.
# Phase 2: the command to run inside the container.

parsing_podman=0

while [[ $# -gt 0 ]]; do
  if [[ "$parsing_podman" == "1" ]]; then
    if [[ "$1" == "--" ]]; then
      parsing_podman=0
      shift
      cmd_args=("$@")
      break
    else
      podman_args+=("$1")
      shift
      continue
    fi
  fi

  if [[ -n "${agent_cmd_json[$1]:-}" ]]; then
    agent="$1"
    shift
    continue
  fi

  case "$1" in
    -h|--help)      want_help=1 ;;

    --ssh)          want_ssh=1 ;;
    --no-ssh)       want_ssh=0 ;;
    --git)          want_git=1 ;;
    --no-git)       want_git=0 ;;
    --gpg-agent)    want_gpg=1 ;;
    --no-gpg-agent) want_gpg=0 ;;
    --gpg-sign)     want_gpg_sign=1 ;;
    --no-gpg-sign)  want_gpg_sign=0 ;;
    --gnupg-private)    want_gnupg_private=1 ;;
    --no-gnupg-private) want_gnupg_private=0 ;;
    --devenv)       want_devenv=1 ;;
    --no-devenv)    want_devenv=0 ;;
    --nix)          want_nix=1 ;;
    --no-nix)       want_nix=0 ;;
    --podman)       want_podman=1 ;;
    --no-podman)    want_podman=0 ;;
    --workspace)    want_workspace=1 ;;
    --no-workspace) want_workspace=0 ;;
    --selinux)      want_selinux=1 ;;
    --no-selinux)   want_selinux=0 ;;

    --ports)        want_ports=1 ;;
    --no-ports)     want_ports=0 ;;
    --ports-dynamic)    want_ports_dynamic=1 ;;
    --no-ports-dynamic) want_ports_dynamic=0 ;;
    --ports-any-interface) want_ports_any_interface=1 ;;
    --firewall)         want_firewall=1 ;;
    --no-firewall)      want_firewall=0 ;;
    --meter-network)    want_meter_network=1 ;;
    --no-meter-network) want_meter_network=0 ;;
    --port)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: --port needs an argument" >&2; exit 1; }
      port_specs+=("$1")
      ;;
    --port=*)       port_specs+=("${1#--port=}") ;;

    -v)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: -v needs an argument" >&2; exit 1; }
      mounts+=("-v" "$(expand_v "$1")")
      ;;
    -v*) mounts+=("-v" "$(expand_v "${1#-v}")") ;;

    --podman-args)
      parsing_podman=1
      ;;
    --privileged)
      podman_args+=("--privileged")
      ;;
    -e|--env)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: -e/--env needs an argument" >&2; exit 1; }
      env_args+=("-e" "$1")
      ;;
    -e*)
      env_args+=("-e" "${1#-e}")
      ;;
    --env=*)
      env_args+=("-e" "${1#--env=}")
      ;;

    --) 
      shift
      cmd_args=("$@")
      break
      ;;

    --*)
      echo "agent-sandbox: '$1' is not an agent-sandbox flag." >&2
      echo "               To pass a podman flag: agent-sandbox --podman-args $1" >&2
      exit 1
      ;;
    *)
      echo "agent-sandbox: unexpected argument '$1'." >&2
      echo "               Valid agents: ${agent_list}" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "$want_help" == "1" ]] || [[ -z "$agent" && ${#cmd_args[@]} -eq 0 ]]; then
  usage
  exit 0
fi

rw_mount_opts="rw"
if [[ "$want_selinux" == "1" ]]; then
  rw_mount_opts="rw,z"
fi

bind_address="127.0.0.1"
if [[ "$want_ports_any_interface" == "1" ]]; then
  bind_address="0.0.0.0"
fi

# ── Agent selection ─────────────────────────────────────────────────────────
if [[ -z "$agent" ]]; then
  agent_argv=()
else
  mapfile -t agent_argv < <(jq -r '.[]' <<< "${agent_cmd_json[$agent]}")
fi

# A devenv.nix in the workspace means project dependencies belong on PATH
# before the agent starts.
if [[ ${#cmd_args[@]} -eq 0 && -n "$agent" ]]; then
  if [[ -f "$PWD/devenv.nix" ]]; then
    cmd_args=(devenv shell --no-tui -- "${agent_argv[@]}")
  else
    cmd_args=("${agent_argv[@]}")
  fi
fi

# ── Workspace ───────────────────────────────────────────────────────────────

if [[ "$want_workspace" == "1" ]]; then
  workspace_name=$(basename "$PWD")
  workspace_dir="/workspace/$workspace_name"
  mounts+=("-v" "$PWD:$workspace_dir:$rw_mount_opts")
else
  workspace_dir="/workspace"
fi

# ── Agent state ─────────────────────────────────────────────────────────────
# Only the selected agent's paths are mounted, so we avoid creating host-side
# state directories for tools that never run.
if [[ -n "$agent" ]]; then
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    mount_rw "$HOME/$rel" "/home/user/$rel"
  done < <(jq -r '.[]' <<< "${agent_state_json[$agent]}")

  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    [[ -s "$HOME/$rel" ]] || printf '{}\n' > "$HOME/$rel"
    mounts+=("-v" "$HOME/$rel:/home/user/$rel:$rw_mount_opts")
  done < <(jq -r '.[]' <<< "${agent_state_files_json[$agent]}")
fi

# ── SSH ─────────────────────────────────────────────────────────────────────

if [[ "$want_ssh" == "1" && -S "${SSH_AUTH_SOCK:-}" ]]; then
  mounts+=("-v" "$SSH_AUTH_SOCK:/agent.sock:$rw_mount_opts")
  env_args+=("-e" "SSH_AUTH_SOCK=/agent.sock")
fi

# ── Git ─────────────────────────────────────────────────────────────────────

if [[ "$want_git" == "1" ]]; then
  git_config_mounted=0
  if [[ -f "$HOME/.gitconfig" ]]; then
    mounts+=("-v" "$HOME/.gitconfig:/home/user/.gitconfig:ro")
    git_config_mounted=1
  fi
  if [[ -f "$HOME/.config/git/config" ]]; then
    mounts+=("-v" "$HOME/.config/git/config:/home/user/.config/git/config:ro")
    git_config_mounted=1
  fi
  if [[ "$git_config_mounted" == "1" ]]; then
    git_name=$(git config --global user.name 2>/dev/null || true)
    git_email=$(git config --global user.email 2>/dev/null || true)
    [[ -n "$git_name" ]]  && env_args+=("-e" "GIT_AUTHOR_NAME=$git_name"   "-e" "GIT_COMMITTER_NAME=$git_name")
    [[ -n "$git_email" ]] && env_args+=("-e" "GIT_AUTHOR_EMAIL=$git_email" "-e" "GIT_COMMITTER_EMAIL=$git_email")
  fi
fi

# ── GnuPG ───────────────────────────────────────────────────────────────────
# The agent socket is forwarded so host keys can sign commits.  The keyring
# directory is a separate decision: it is only exposed when it holds no usable
# secret on disk (the smart-card case), unless --gnupg-private overrides.

if [[ "$want_gpg" == "1" ]]; then
  if command -v gpgconf >/dev/null 2>&1; then
    gpg_socket=$(gpgconf --list-dir agent-socket 2>/dev/null || true)
  fi
  gpg_socket="${gpg_socket:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/gnupg/S.gpg-agent}"
  if [[ -S "$gpg_socket" ]]; then
    mounts+=("-v" "$gpg_socket:/run/host-gpg-agent:ro")
    env_args+=("-e" "AGENT_SANDBOX_GPG_AGENT=1")
  fi

  if [[ -d "$HOME/.gnupg" ]]; then
    gnupg_offenders=""
    gnupg_status=0
    gnupg_offenders=$(agent-sandbox-gnupg-scan "$HOME/.gnupg") || gnupg_status=$?

    if [[ "$gnupg_status" == "0" || "$want_gnupg_private" == "1" ]]; then
      if [[ "$gnupg_status" != "0" ]]; then
        echo "agent-sandbox: exposing ~/.gnupg with on-disk secret keys (--gnupg-private)." >&2
      fi
      # Public material only: the keyring so gpg can name the signing key, and
      # the trust database so it believes the answer.
      for keyring in pubring.kbx pubring.gpg trustdb.gpg; do
        if [[ -f "$HOME/.gnupg/$keyring" ]]; then
          mounts+=("-v" "$HOME/.gnupg/$keyring:/run/host-gnupg/$keyring:ro")
        fi
      done
      if [[ "$want_gnupg_private" == "1" && -d "$HOME/.gnupg/private-keys-v1.d" ]]; then
        mounts+=("-v" "$HOME/.gnupg/private-keys-v1.d:/run/host-gnupg/private-keys-v1.d:ro")
      fi
    else
      echo "agent-sandbox: not exposing ~/.gnupg -- it holds secret keys on disk:" >&2
      while IFS= read -r offender; do
        printf '               %s\n' "$offender" >&2
      done <<< "$gnupg_offenders"
      echo "               A smart-card setup keeps only stubs here and is exposed normally." >&2
      echo "               Override with --gnupg-private, or silence this with --no-gpg-agent." >&2
      exit 1
    fi
  fi
fi

if [[ "$want_gpg_sign" == "0" ]]; then
  env_args+=("-e" "GIT_CONFIG_COUNT=1")
  env_args+=("-e" "GIT_CONFIG_KEY_0=commit.gpgsign")
  env_args+=("-e" "GIT_CONFIG_VALUE_0=false")
fi

# ── devenv / nix ────────────────────────────────────────────────────────────

if [[ "$want_devenv" == "1" ]]; then
  mount_rw "$HOME/.local/share/devenv" /home/user/.local/share/devenv
fi

if [[ "$want_nix" == "1" ]]; then
  daemon_socket=/nix/var/nix/daemon-socket/socket
  if [[ -S "$daemon_socket" ]]; then
    # Multi-user nix: read-only store, builds delegated to the host daemon.
    mounts+=("-v" "/nix/store:/nix/store:ro")
    mounts+=("-v" "$daemon_socket:/nix/var/nix/daemon-socket/socket:$rw_mount_opts")
    env_args+=("-e" "NIX_REMOTE=daemon")
  elif [[ -d /nix/store ]]; then
    # Single-user nix: overlay, so the container can write without touching
    # the host store.
    mounts+=("-v" "/nix:/nix:O")
  fi
  env_args+=("-e" "AGENT_SANDBOX_HOST_NIX=1")
fi

# ── Host podman socket ──────────────────────────────────────────────────────

if [[ "$want_podman" == "1" ]]; then
  host_socket="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  if [[ -S "$host_socket" ]]; then
    mounts+=("-v" "$host_socket:/run/podman/podman.sock:$rw_mount_opts")
    env_args+=("-e" "CONTAINER_HOST=unix:///run/podman/podman.sock")
    env_args+=("-e" "DOCKER_HOST=unix:///run/podman/podman.sock")
  else
    echo "agent-sandbox: --podman requested but no socket at $host_socket." >&2
    echo "               Start it with: systemctl --user start podman.socket" >&2
  fi
fi

# ── Ports ───────────────────────────────────────────────────────────────────
# Two sources, both ending as validated bind:host:container/proto triples.
# Nothing from AGENTS.md is ever passed to podman as an argument of its own.

publish_args=()
published=()

for spec in "${port_specs[@]}"; do
  triple=$(parse_port_spec "$spec")
  publish_args+=("-p" "$triple")
  published+=("$triple")
done

if [[ "$want_ports" == "1" && -f "$PWD/AGENTS.md" ]]; then
  parse_flags=()
  [[ "$want_ports_any_interface" == "1" ]] && parse_flags+=(--ports-any-interface)
  if ! declared=$(agent-sandbox-parse-agents "${parse_flags[@]}" "$PWD/AGENTS.md"); then
    echo "agent-sandbox: refusing to launch on an invalid [ports] block (use --no-ports to skip)." >&2
    exit 1
  fi
  while IFS= read -r triple; do
    [[ -n "$triple" ]] || continue
    publish_args+=("-p" "$triple")
    published+=("$triple")
  done <<< "$declared"
fi

# Publishing a port and running a proxy are mutually exclusive, because the two
# network topologies contradict each other.  The shared network below is a normal
# NAT bridge, and the sandbox would be attached to it *as well as* the proxy's
# --internal network -- giving it a route to the internet that does not pass
# through the proxy at all.  The firewall would still filter what went through
# it, and everything else would simply go around.
#
# Checked here: after the [ports] block is parsed, so a declaration that yields
# nothing is not treated as a request, and before any network is created, so the
# refusal leaves nothing behind.
if [[ "$want_firewall" == "1" || "$want_meter_network" == "1" ]]; then
  proxy_flag="--firewall"
  [[ "$want_firewall" == "1" ]] || proxy_flag="--meter-network"

  conflict=""
  if [[ ${#published[@]} -gt 0 ]]; then
    conflict="a published port (${published[0]})"
  elif [[ "$want_ports_dynamic" == "1" ]]; then
    conflict="--ports-dynamic"
  fi

  if [[ -n "$conflict" ]]; then
    echo "agent-sandbox: $proxy_flag cannot be combined with $conflict." >&2
    echo "               A published port puts the sandbox on the shared bridge network," >&2
    echo "               which routes to the internet around the proxy, so the policy" >&2
    echo "               would only be advisory." >&2
    echo "               Drop the port, or drop $proxy_flag." >&2
    exit 1
  fi
fi

# A shared network is what makes `agent-sandbox-ctl port add` possible later:
# podman cannot add a binding to a running container, so a sidecar has to
# reach this one by name.  Created lazily so that a launch with no ports at
# all keeps podman's default rootless networking untouched.
network_args=()
if [[ ${#published[@]} -gt 0 || "$want_ports_dynamic" == "1" ]]; then
  if ! podman network exists "$AGENT_SANDBOX_NETWORK" 2>/dev/null; then
    podman network create "$AGENT_SANDBOX_NETWORK" >/dev/null
  fi
  network_args=(--network "$AGENT_SANDBOX_NETWORK")
fi

if [[ ${#published[@]} -gt 0 ]]; then
  echo "agent-sandbox: publishing ${published[*]}" >&2
  echo "               (a server inside must bind 0.0.0.0, not 127.0.0.1)" >&2
fi

# ── Identity ────────────────────────────────────────────────────────────────

# Temp passwd/group so tools resolve the username inside the container.
passwd_tmp=$(mktemp)
group_tmp=$(mktemp)

# Declared before the trap is installed: it fires on any signal, including one
# that arrives between here and the sidecar block below, and under nounset an
# unset variable would abort the trap partway through cleaning up.
sidecar_id=""
sidecar_shared=""
sidecar_policy=""

cleanup() {
  rm -f "$passwd_tmp" "$group_tmp"
  if [[ -n "$sidecar_id" ]]; then
    podman stop -t 1 "$sidecar_id" >/dev/null 2>&1 || true
    # Not --rm: a sidecar that exits before signalling readiness has to stay
    # around long enough for `podman logs` to say why.
    podman rm -f "$sidecar_id" >/dev/null 2>&1 || true

    if [[ "$want_meter_network" == "1" ]]; then
      # || true: this runs inside the EXIT trap under errexit, and the rm -rf
      # below still has to happen even if the report cannot be rendered.
      agent-sandbox-network-summary "$sidecar_shared/connections.jsonl" || true
      # The rm -rf below would take the per-connection timings with it, and
      # those are what distinguish "failed instantly" from "burned the whole
      # retry window".  Keep the log whenever anything went wrong.
      if grep -q '"verdict":"\(deny\|error\)"' "$sidecar_shared/connections.jsonl" 2>/dev/null; then
        saved_log="${TMPDIR:-/tmp}/agent-sandbox-connections-$$.jsonl"
        if cp "$sidecar_shared/connections.jsonl" "$saved_log" 2>/dev/null; then
          printf '  connection log kept at %s\n\n' "$saved_log"
        fi
      fi
    fi

    # podman tears a --rm container down asynchronously after `stop` returns, so
    # a single attempt here loses the race often enough to leak one --internal
    # network per session -- and each of those holds a subnet from the rootless
    # pool until `agent-sandbox-ctl purge` reclaims it.
    for _ in $(seq 1 20); do
      podman network rm "$sidecar_id" >/dev/null 2>&1 && break
      podman network exists "$sidecar_id" 2>/dev/null || break
      sleep 0.25
    done

    [[ -n "$sidecar_shared" ]] && rm -rf "$sidecar_shared"
    [[ -n "$sidecar_policy" ]] && rm -rf "$sidecar_policy"
  fi
}
trap cleanup EXIT
printf 'root:x:0:0:root:/root:/bin/sh\nuser:x:%s:%s::/home/user:/bin/bash\nnobody:x:65534:65534:Nobody:/:/bin/sh\n' "$(id -u)" "$(id -g)" > "$passwd_tmp"
printf 'root:x:0:\nuser:x:%s:\nnobody:x:65534:\n' "$(id -g)" > "$group_tmp"

# Include the hashed workspace path and the launcher PID in the container name so
# agent-sandbox-ctl port and agent-sandbox-ctl purge find sandboxes without guessing
# network/PID relationships.
workspace_slug=$(basename "$PWD")
workspace_slug="${workspace_slug//[^A-Za-z0-9_.-]/-}"
container_name="agent-sandbox-${workspace_slug:0:32}-$$"

# ── Sidecar Proxy & Metering ────────────────────────────────────────────────
if [[ "$want_firewall" == "1" || "$want_meter_network" == "1" ]]; then
  sidecar_id="agent-sandbox-sidecar-$(head -c 12 /proc/sys/kernel/random/uuid 2>/dev/null || echo $$)"
  # Identifiable templates, so `agent-sandbox-ctl purge` can recognise the dirs
  # left behind by a launcher that was killed before its trap could run.
  sidecar_shared=$(mktemp -d -t "agent-sandbox-sidecar-XXXXXXXX")
  sidecar_policy=$(mktemp -d -t "agent-sandbox-policy-XXXXXXXX")
  # --disable-dns is load-bearing, not tidiness.  Podman routes a container's
  # whole resolver through aardvark-dns as soon as *any* of its networks has
  # dns_enabled -- podman-run(1), under --dns: "passing a custom network whose
  # dns_enabled is set to true to --network will result in /etc/resolv.conf only
  # referring to the aardvark-dns server".  And aardvark has refused to forward
  # for --internal networks since 1.11.0 ("Do not allow 'internal' networks to
  # access DNS"), so the sidecar's only nameserver would be one that answers
  # NXDOMAIN to every external name.  That is the "dns: Name or service not
  # known" 502, and it is why the --dns servers below were inert: they were
  # demoted to an aardvark upstream that aardvark then declined to use.
  #
  # With DNS off on both of the sidecar's networks there is no aardvark in the
  # path at all and --dns lands in resolv.conf verbatim.  The cost is that the
  # sandbox can no longer resolve the sidecar by container name, which is why
  # HTTP_PROXY is addressed by IP further down.
  #
  # Not `|| true`: the known failure is a rootless subnet pool exhausted by
  # leaked networks, and swallowing it just moves the error to `podman run`,
  # where it reads as an unrelated problem.
  if ! podman network create --internal --disable-dns "$sidecar_id" >/dev/null; then
    echo "agent-sandbox: could not create the sidecar network $sidecar_id" >&2
    echo "               (leaked networks exhaust the rootless subnet pool:" >&2
    echo "                reclaim them with 'agent-sandbox-ctl purge')" >&2
    exit 1
  fi

  # The policy file is the single channel by which policy reaches the proxy.  It
  # replaced four separately-encoded arguments, where a space-separated list met a
  # comma-separated parser and every entry past the first was silently dropped --
  # which for an allow list means allowing everything.
  #
  # Written into a directory mounted ro into the sidecar and NOT into the sandbox:
  # the agent must not be able to widen the firewall that contains it.
  : > "$sidecar_policy/policy"
  if [[ "$want_firewall" == "1" && -f "$PWD/AGENTS.md" ]]; then
    # Strict, like the [ports] block above: a policy the operator got wrong must
    # not silently become no policy at all.
    if ! agent-sandbox-parse-agents --proxy-policy "$PWD/AGENTS.md" \
         > "$sidecar_policy/policy"; then
      echo "agent-sandbox: refusing to launch on an invalid [proxy] block (use --no-firewall to skip)." >&2
      exit 1
    fi
  fi
  # Kept pristine so `agent-sandbox-ctl firewall reset` has something to restore
  # and `firewall show` can tell declared rules from ones added at runtime.
  cp "$sidecar_policy/policy" "$sidecar_policy/policy.base"

  if [[ "$want_firewall" == "1" ]] && ! grep -q '^allow_' "$sidecar_policy/policy"; then
    echo "agent-sandbox: --firewall is active with no allow rules, so every host is allowed." >&2
    echo "               Declare allow_domains/allow_ips in a [proxy] block to restrict it." >&2
  fi

  # NET_ADMIN backs the blackhole routes installed for deny_ips.  Metering used
  # to also need NET_RAW for packet capture; it is now accounted by the proxy.
  sidecar_caps=("--cap-add=NET_ADMIN")

  # Nameservers for the sidecar, read from the host.  With DNS disabled on both
  # of its networks (see --disable-dns above) these land in the container's
  # /etc/resolv.conf verbatim and are queried directly, rather than becoming an
  # upstream for an aardvark that would refuse to use it.
  #
  # Only bare IP literals survive the filter.  A scoped address -- "fe80::1%eth0",
  # which RA-configured hosts do write -- is rejected by podman, and a rejected
  # --dns takes the whole sidecar down.  Loopback and link-local entries are
  # dropped for a different reason: they name a resolver on the *host's* stack,
  # which is not reachable from the container's netns.
  usable_nameservers() { # FILE
    [[ -r "$1" ]] || return 0
    local line candidate lower
    # `|| [[ -n "$line" ]]` so a file with no trailing newline does not lose its
    # last entry -- silently dropping a nameserver is how this whole area got
    # its reputation.
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*nameserver[[:space:]]+([^[:space:]]+) ]] || continue
      candidate="${BASH_REMATCH[1]}"
      lower="${candidate,,}"
      case "$lower" in
        127.*|169.254.*|::1|fe80:*|*%*) continue ;;
      esac
      [[ "$candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$candidate" =~ ^[0-9A-Fa-f:]+$ ]] \
        || continue
      printf '%s\n' "$candidate"
    done < "$1"
  }

  sidecar_nameservers=()
  mapfile -t sidecar_nameservers < <(usable_nameservers /etc/resolv.conf)
  # systemd-resolved publishes 127.0.0.53 as the only nameserver, which the
  # filter above correctly discards.  Its own file carries the real upstreams;
  # using them keeps split-horizon and corporate names resolving instead of
  # quietly defecting to a public resolver.
  if [[ ${#sidecar_nameservers[@]} -eq 0 ]]; then
    mapfile -t sidecar_nameservers < <(usable_nameservers /run/systemd/resolve/resolv.conf)
  fi
  if [[ ${#sidecar_nameservers[@]} -eq 0 ]]; then
    sidecar_nameservers=(8.8.8.8 1.1.1.1)
  fi

  sidecar_dns_args=()
  for sidecar_ns in "${sidecar_nameservers[@]}"; do
    sidecar_dns_args+=(--dns "$sidecar_ns")
  done

  # The sidecar is our infrastructure container, not the sandboxed agent code.
  # Disable SELinux labeling so it can write the readiness marker and the
  # connection log into the shared volume.
  sidecar_selinux=()
  if [[ "$want_selinux" == "1" ]]; then
    sidecar_selinux=("--security-opt" "label=disable")
  fi

  # Not --rm: the cleanup trap removes it, so a sidecar that dies early is still
  # around for `podman logs` to explain itself.
  #
  # Labelled like every other container the project creates: without this the
  # sidecar could only be found by guessing at its random name, which is why
  # nothing could report on the firewall or reach the proxy's log.  target= points
  # back at the sandbox, mirroring the port forwarders.
  # stdout is just the container id, so it goes to /dev/null -- but stderr does
  # not.  Under errexit a silenced failure here aborted the launcher with no
  # output whatsoever, which is the worst possible way to learn that a --dns
  # value or a mount was rejected.
  if ! podman run -d --name "$sidecar_id" \
    --label "agent-sandbox.role=proxy" \
    --label "agent-sandbox.target=$container_name" \
    --label "agent-sandbox.workspace=$PWD" \
    --network bridge --network "$sidecar_id" \
    "${sidecar_dns_args[@]}" \
    "${sidecar_selinux[@]}" \
    "${sidecar_caps[@]}" -v "$sidecar_shared:/sidecar_shared:$rw_mount_opts" \
    -v "$sidecar_policy:/sidecar_policy:ro" \
    -e "FIREWALL=$want_firewall" \
    "$AGENT_SANDBOX_IMAGE" agent-sandbox-sidecar >/dev/null; then
    echo "agent-sandbox: could not start the proxy sidecar" >&2
    exit 1
  fi

  # Wait for the sidecar to signal readiness via the shared volume.  It writes
  # that marker only after the proxy can resolve names (see wait_for_egress in
  # proxy/src/main.rs) and after the blackhole routes are installed, so this has
  # to outlast the proxy's own READY_TIMEOUT -- cutting it short would start the
  # agent against a proxy that cannot reach anything yet, which is exactly the
  # race this fixes.
  sidecar_ready=0
  for _ in $(seq 1 350); do
    if [[ -f "$sidecar_shared/ready" ]]; then
      sidecar_ready=1
      break
    fi
    # A rejected policy exits the proxy immediately; waiting out the full 35s
    # would bury the reason under a timeout that suggests a network problem.
    if ! podman container inspect --format '{{.State.Running}}' "$sidecar_id" 2>/dev/null \
         | grep -qx true; then
      echo "agent-sandbox: the proxy sidecar exited before signalling readiness:" >&2
      podman logs "$sidecar_id" 2>&1 | sed 's/^/               /' >&2
      exit 1
    fi
    sleep 0.1
  done
  if [[ "$sidecar_ready" != "1" ]]; then
    echo "agent-sandbox: warning: proxy did not signal readiness in 35s" >&2
    echo "               (continuing; check: podman logs $sidecar_id)" >&2
  fi

  # The proxy starts even when it could not prove egress -- a degraded launch
  # beats a hung one -- but that used to be visible only in the sidecar's log,
  # so the session looked healthy right up until the first request came back
  # 502.  Say it here, where the person who ran the command is looking.
  if [[ -s "$sidecar_shared/egress-degraded" ]]; then
    echo "agent-sandbox: warning: the proxy could not resolve names at startup" >&2
    sed 's/^/               /' "$sidecar_shared/egress-degraded" >&2
    echo "               (continuing; requests may fail. Full log: agent-sandbox-ctl logs)" >&2
  fi

  network_args+=(--network "$sidecar_id")
  # /sidecar_shared is deliberately NOT mounted into the sandbox.  It used to be,
  # for the sake of agent-sandbox-allow (now gone), and since the sandbox runs
  # --userns=keep-id it had write access to connections.jsonl -- so the agent
  # could truncate or forge the log of its own network activity.  Nothing inside
  # needs the directory: the readiness marker is read by the launcher on the host,
  # and `agent-sandbox-ctl net` reads the log through the sidecar.
  #
  # By address, not by name.  The internal network is --disable-dns (see the
  # network create above), so there is no aardvark to resolve the sidecar's
  # container name -- and even when there was, nothing in the readiness
  # handshake proved aardvark had published the record before the sandbox
  # started, which is one more startup race that simply stops existing here.
  sidecar_ip=""
  for _ in $(seq 1 20); do
    # `container inspect`, not plain `inspect`: the network carries the same
    # name, and which one a bare inspect resolves to is podman's business.
    sidecar_ip=$(podman container inspect --format \
      "{{(index .NetworkSettings.Networks \"$sidecar_id\").IPAddress}}" \
      "$sidecar_id" 2>/dev/null) || sidecar_ip=""
    [[ -n "$sidecar_ip" ]] && break
    sleep 0.1
  done
  if [[ -z "$sidecar_ip" ]]; then
    echo "agent-sandbox: the proxy sidecar has no address on $sidecar_id" >&2
    echo "               (check: podman logs $sidecar_id)" >&2
    exit 1
  fi

  env_args+=("-e" "HTTP_PROXY=http://$sidecar_ip:8888" "-e" "HTTPS_PROXY=http://$sidecar_ip:8888")
fi

env_args+=("-e" "TERM=${TERM:-xterm-256color}")
[[ -n "${COLORTERM:-}" ]] && env_args+=("-e" "COLORTERM=$COLORTERM")

# Recorded as a label so `agent-sandbox-ctl list` can show it and `port add` can
# refuse to weaken it.  Always set, including "off": an absent label is
# indistinguishable from a container created before this existed, which would
# make the column ambiguous exactly when it matters.
proxy_mode=off
if [[ "$want_firewall" == "1" ]]; then
  proxy_mode=firewall
elif [[ "$want_meter_network" == "1" ]]; then
  proxy_mode=meter
fi

# Only allocate a TTY when there is one to allocate, so piped and CI
# invocations (agent-sandbox -- bash -c '…' | tee log) still work.
# GPG_TTY is deliberately not set here: the correct value is the tty podman
# allocates inside the container, which only the entrypoint can observe.
tty_args=()
if [[ -t 0 && -t 1 ]]; then
  tty_args=(--tty)
fi

# Not exec'd: the EXIT trap above still has temp files to clean up.
podman run \
  --rm \
  --interactive \
  "${tty_args[@]}" \
  --userns=keep-id \
  --name "$container_name" \
  --label "agent-sandbox.role=sandbox" \
  --label "agent-sandbox.workspace=$PWD" \
  --label "agent-sandbox.proxy=$proxy_mode" \
  --workdir "$workspace_dir" \
  -e HOME=/home/user \
  -v "$passwd_tmp:/etc/passwd:ro" \
  -v "$group_tmp:/etc/group:ro" \
  --mount type=tmpfs,dst=/home/user/.config,U=true \
  --mount type=tmpfs,dst=/home/user/.cache,U=true \
  --mount type=tmpfs,dst=/home/user/.local,U=true \
  "${network_args[@]}" \
  "${publish_args[@]}" \
  "${mounts[@]}" \
  "${env_args[@]}" \
  "${podman_args[@]}" \
  "$AGENT_SANDBOX_IMAGE" \
  "${cmd_args[@]}"
