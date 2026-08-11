#!/usr/bin/env bash
# One screen of state for a running sandbox.
#
# Deliberately an index, not a report: counts and names only, each line ending in
# the command that shows the detail.  `net` renders traffic, `firewall show`
# renders the policy, `port ls` renders the forwards; if this printed those
# lists too there would be three commands disagreeing about the same thing.

usage() {
  cat <<'USAGE'
agent-sandbox-status [SANDBOX] [--sandbox NAME] [--export]

Summarises one running sandbox: workspace, proxy mode, policy and traffic
counts, and published ports.  Each line names the command that shows more.
With --export, prints the configuration in AGENTS.md TOML format instead.

With one sandbox running, --sandbox may be omitted.
USAGE
}

export_toml=0
sandbox_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "${0##*/}: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    --export)    export_toml=1 ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
       if [[ -z "$sandbox_name" ]]; then
         sandbox_name="$1"
       else
         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1
       fi
       ;;
  esac
  shift
done

if [[ -n "$sandbox_name" && ! "$sandbox_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "${0##*/}: invalid sandbox name: $sandbox_name" >&2
  exit 1
fi

sandbox=$(resolve_sandbox "$sandbox_name" --running)
workspace_dir=$(sandbox_workspace "$sandbox")
sidecar=$(sidecar_for_sandbox "$sandbox")

if [[ "$export_toml" == "1" ]]; then
  echo '```toml agent-sandbox'

  # ── Proxy ───────────────────────────────────────────────────────────────────
  if [[ -n "$sidecar" ]]; then
    policy_dir=$(sidecar_mount "$sidecar" /sidecar_policy)
    if [[ -n "$policy_dir" && -r "$policy_dir/policy" ]]; then
      # Baseline entries (always enforced regardless of AGENTS.md) are omitted
      # from the export so the output round-trips cleanly.  Falls back to
      # /dev/null when the sidecar predates policy.baseline.
      baseline_file="${policy_dir}/policy.baseline"
      [[ -f "$baseline_file" ]] || baseline_file="/dev/null"
      proxy_toml=$(awk -v baseline="$baseline_file" '
        BEGIN {
          while ((getline line < baseline) > 0) {
            split(line, a, " "); skip[a[1]" "a[2]] = 1
          }
          close(baseline)
        }
        $1 ~ /^(allow_domains|deny_domains|allow_ips|deny_ips|allow_ports)$/ {
          if (!skip[$1" "$2])
            list[$1] = list[$1] "\"" $2 "\", "
        }
        $1 == "default" { def = $2 }
        END {
          for (k in list) {
            val = list[k]
            sub(/, $/, "", val)
            print k " = [" val "]"
          }
          if (def != "") print "default = \"" def "\""
        }
      ' "$policy_dir/policy")
      
      if [[ -n "$proxy_toml" ]]; then
        echo "[proxy]"
        echo "$proxy_toml"
        echo ""
      fi
    fi
  fi

  # ── Ports ───────────────────────────────────────────────────────────────────
  ports_lines=()
  port_idx=1
  add_ports() {
    local output="$1"
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]*-[^:]*:[^0-9]*([0-9.]+|\[.*\]):([0-9]+)$ ]]; then
        local container="${BASH_REMATCH[1]}"
        local proto="${BASH_REMATCH[2]}"
        local bind="${BASH_REMATCH[3]}"
        local host="${BASH_REMATCH[4]}"
        ports_lines+=("port_$port_idx = { container = $container, host = $host, bind = \"$bind\", protocol = \"$proto\" }")
        ((port_idx++))
      fi
    done <<< "$output"
  }
  add_ports "$(podman port "$sandbox" 2>/dev/null || true)"
  forwarders=$(podman ps --filter "label=agent-sandbox.role=port-forward" \
                         --filter "label=agent-sandbox.target=$sandbox" \
                         --format '{{.Names}}' 2>/dev/null || true)
  for fwd in $forwarders; do
    add_ports "$(podman port "$fwd" 2>/dev/null || true)"
  done

  if [[ ${#ports_lines[@]} -gt 0 ]]; then
    echo "[ports]"
    for line in "${ports_lines[@]}"; do
      echo "$line"
    done
    echo ""
  fi

  # ── Mounts ──────────────────────────────────────────────────────────────────
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
    echo "[mounts]"
    echo "$mounts_toml"
    echo ""
  fi

  echo '```'
  exit 0
fi

row() { printf '  %-12s%s\n' "$1" "$2"; }

printf '%s\n' "$sandbox"
row workspace "$workspace_dir"
row uptime    "$(podman ps --filter "name=^${sandbox}\$" --format '{{.Status}}' 2>/dev/null)"

mode=$(sandbox_proxy_mode "$sandbox")
case "$mode" in
  firewall|meter) row proxy "$mode  ($sidecar)" ;;
  off)            row proxy "off  (direct network access)" ;;
  # Pre-dates the label: fall back to whether a sidecar is actually there.
  *)              row proxy "$([[ -n "$sidecar" ]] && echo "on  ($sidecar)" || echo unknown)" ;;
esac

networks=$(podman inspect --format \
  '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}' "$sandbox" 2>/dev/null || true)
[[ -n "${networks// /}" ]] && row networks "${networks% }"

# ── policy ──────────────────────────────────────────────────────────────────

if [[ -n "$sidecar" ]]; then
  policy_dir=$(sidecar_mount "$sidecar" /sidecar_policy)
  if [[ -n "$policy_dir" && -r "$policy_dir/policy" ]]; then
    rules=$(grep -cE '^(allow|deny)_' "$policy_dir/policy" 2>/dev/null || true)
    if grep -q '^allow_' "$policy_dir/policy" 2>/dev/null; then
      default=deny
    else
      default=allow
    fi
    if grep -q '^default ' "$policy_dir/policy" 2>/dev/null; then
      default=$(awk '$1 == "default" { print $2 }' "$policy_dir/policy" | tail -n 1)
    fi
    row firewall "${rules:-0} rule(s), default $default        agent-sandbox-ctl firewall show"
  fi

  # ── traffic ───────────────────────────────────────────────────────────────

  log=$(sidecar_mount "$sidecar" /sidecar_shared)
  if [[ -n "$log" && -r "$log/connections.jsonl" ]]; then
    # In flight is opens minus closes, not opens minus allows: a record written
    # before open/close events existed has no "ev" at all, and counting those as
    # closes would report a negative or phantom backlog.
    counts=$(awk '
      /"ev":"open"/ { opens++; next }
      {
        if (/"ev":"close"/)      closes++
        if (/"verdict":"allow"/) ok++
        else if (/"verdict":"deny"/)  deny++
        else if (/"verdict":"error"/) err++
      }
      END {
        live = opens - closes
        if (live < 0) live = 0
        printf "%d %d %d %d", ok+0, deny+0, err+0, live
      }
    ' "$log/connections.jsonl")
    read -r ok deny err live <<< "$counts"
    summary="$ok connection(s)"
    [[ "$deny" -gt 0 ]] && summary+=", $deny denied"
    [[ "$err" -gt 0 ]] && summary+=", $err failed"
    [[ "$live" -gt 0 ]] && summary+=", $live in flight"
    row network "$summary        agent-sandbox-ctl net"
    row log "                         agent-sandbox-ctl logs"
  fi
fi

# ── ports ───────────────────────────────────────────────────────────────────

published=$(podman port "$sandbox" 2>/dev/null | tr '\n' ' ' || true)
forwarded=$(podman ps --filter "label=agent-sandbox.role=port-forward" \
                      --filter "label=agent-sandbox.target=$sandbox" \
                      --format '{{.Names}}' 2>/dev/null | wc -l)
if [[ -n "${published// /}" || "$forwarded" -gt 0 ]]; then
  detail="${published:-}"
  [[ "$forwarded" -gt 0 ]] && detail+="($forwarded forwarder(s))"
  row ports "$detail        agent-sandbox-ctl port ls"
else
  row ports "none published        agent-sandbox-ctl port add"
fi
