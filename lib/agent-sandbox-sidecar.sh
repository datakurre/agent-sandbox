#!/usr/bin/env bash
set -euo pipefail

# Entry point of the proxy sidecar container.
#
# Policy comes from /sidecar_policy/policy, mounted read-only from the host and
# deliberately NOT mounted into the sandbox: the agent must not be able to widen
# the firewall that contains it.  This script does not interpret the policy
# beyond pulling out deny_ips for the kernel blackhole routes -- the proxy is the
# reference reader, and it validates before anything observable happens.
#
# Ordering matters and is the reason for two readiness markers:
#
#   1. the proxy validates the policy and probes egress, then writes proxy-ready
#   2. this script installs the blackhole routes
#   3. only then does it write `ready`, which is what the launcher waits for
#
# So the routes are guaranteed to be in place before the sandbox exists, and an
# unparseable policy stops the proxy (exit 2) before touching the kernel table.

policy_file=/sidecar_policy/policy

# Metering is accounted by the proxy itself, which already knows the host, the
# byte counts in each direction and the verdict for every connection.  Capturing
# packets instead would write a second full copy of every transferred byte to
# disk, which is what made throughput degrade as a session went on.
#
# Written whenever a proxy runs, not only under --meter-network, so that
# `agent-sandbox-ctl net` can report on a --firewall session too -- which is
# where "why was this blocked?" actually gets asked.  A few hundred bytes per
# connection into a directory the launcher removes at exit.  --meter-network
# decides only whether the summary is printed when the session ends.
metrics_log=/sidecar_shared/connections.jsonl

# Both side effects go through these so the tests can run the whole script
# without a container: podman is not available in a nix build.  Dry-run also
# relocates the two container paths, which do not exist outside one.
if [[ "${AGENT_SANDBOX_SIDECAR_DRY_RUN:-0}" == "1" ]]; then
  run_ip()    { echo "ip $*"; }
  run_proxy() { echo "agent-sandbox-proxy $*"; }
  # There is no route table to read outside a container, and echoing the query
  # back would parse as a route named "-o".
  installed_blackholes() { :; }
  policy_file="${AGENT_SANDBOX_SIDECAR_POLICY:-$policy_file}"
  metrics_log=/dev/null
else
  run_ip()    { ip "$@"; }
  run_proxy() { agent-sandbox-proxy "$@"; }
  installed_blackholes() { ip -o route show type blackhole 2>/dev/null | awk '{ print $2 }'; }
fi

# Graceful shutdown: track the proxy PID and forward signals.
proxy_pid=""
cleanup() {
  [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Values of one policy key, one per line.
policy_values() {
  [[ -f "$policy_file" ]] || return 0
  while read -r key value _rest; do
    [[ "$key" == "$1" ]] || continue
    [[ -n "${value:-}" ]] || continue
    printf '%s\n' "$value"
  done < "$policy_file"
}

# Defence in depth behind the proxy's own deny_ips check: a route the sandbox
# cannot use at all, in case anything ever reaches the sidecar's netns without
# passing through the proxy.  Needs --cap-add=NET_ADMIN.
#
# Reconciles against the kernel rather than against a remembered list, so there
# is no state to keep in sync and nothing to get wrong after a restart.  The
# proxy watches the same file independently; while the two briefly disagree both
# are still deny mechanisms, and the proxy is the one the traffic traverses.
in_list() {
  local needle="$1" item
  shift
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

sync_blackholes() {
  local want=() have=() entry
  mapfile -t want < <(policy_values deny_ips)
  mapfile -t have < <(installed_blackholes)

  for entry in ${want[@]+"${want[@]}"}; do
    [[ -n "$entry" ]] || continue
    in_list "$entry" ${have[@]+"${have[@]}"} && continue
    # Not fatal -- the proxy is the enforcing layer -- but no longer silent:
    # a rejected route used to vanish into `|| true`.
    run_ip route add blackhole "$entry" \
      || echo "sidecar: cannot blackhole $entry" >&2
  done

  for entry in ${have[@]+"${have[@]}"}; do
    [[ -n "$entry" ]] || continue
    in_list "$entry" ${want[@]+"${want[@]}"} && continue
    run_ip route del blackhole "$entry" \
      || echo "sidecar: cannot un-blackhole $entry" >&2
  done
}

# Rely entirely on Podman's /etc/resolv.conf configuration instead of trying to
# strip it.

proxy_args=(--log "$metrics_log")
if [[ "${FIREWALL:-0}" == "1" ]]; then
  if [[ ! -f "$policy_file" ]]; then
    echo "sidecar: --firewall was requested but $policy_file is missing" >&2
    exit 1
  fi
  proxy_args+=(--policy "$policy_file")
fi
# Metering only: no policy at all, so the proxy allows everything and just
# accounts it.

if [[ "${AGENT_SANDBOX_SIDECAR_DRY_RUN:-0}" == "1" ]]; then
  run_proxy "${proxy_args[@]}"
  sync_blackholes
  exit 0
fi

run_proxy "${proxy_args[@]}" &
proxy_pid=$!

# The proxy gates proxy-ready on a working name lookup, so allow for its full
# READY_TIMEOUT.  Give up if it dies first: with a rejected policy it exits
# immediately, and waiting out the timeout would hide the reason.
for _ in $(seq 1 350); do
  [[ -f /sidecar_shared/proxy-ready ]] && break
  kill -0 "$proxy_pid" 2>/dev/null || break
  sleep 0.1
done

if ! kill -0 "$proxy_pid" 2>/dev/null; then
  echo "sidecar: the proxy exited before signalling readiness" >&2
  wait "$proxy_pid"   # propagate its exit status (2 = bad policy)
  exit 1
fi

sync_blackholes

# Tells the launcher the sandbox may start.
printf 'ready\n' > /sidecar_shared/ready

# The policy can change while the session runs (agent-sandbox-ctl firewall), and
# the proxy reloads it on its own; these routes have to follow.  Same interval,
# and cheap: one `ip route show` per second.
while kill -0 "$proxy_pid" 2>/dev/null; do
  sleep 1
  sync_blackholes
done

wait "$proxy_pid"
