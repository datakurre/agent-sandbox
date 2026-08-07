#!/usr/bin/env bash
set -euo pipefail

# Graceful shutdown: track the proxy PID and forward signals.
proxy_pid=""
cleanup() {
  [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Rely entirely on Podman's /etc/resolv.conf configuration instead of trying to strip it

if [[ "${FIREWALL:-0}" == "1" && -n "${PROXY_DENY_IPS:-}" ]]; then
  read -ra deny_ips <<< "$PROXY_DENY_IPS"
  for ip in "${deny_ips[@]}"; do
    ip route add blackhole "$ip" || true
  done
fi

# Metering is accounted by the proxy itself, which already knows the host, the
# byte counts in each direction and the verdict for every connection.  Capturing
# packets instead would write a second full copy of every transferred byte to
# disk, which is what made throughput degrade as a session went on.
metrics_log=""
if [[ "${METER_NETWORK:-0}" == "1" ]]; then
  metrics_log=/sidecar_shared/connections.jsonl
fi

# The proxy resolves "more specific wins" for both domains and IPs itself; see
# proxy/src/main.rs.
if [[ "${FIREWALL:-0}" == "1" ]]; then
  # Re-construct allow_domains from positional arguments
  allow_domains_csv=""
  if [[ $# -gt 0 ]]; then
    allow_domains_csv="$(IFS=,; echo "$*")"
  fi

  agent-sandbox-proxy "$allow_domains_csv" "${PROXY_DENY_DOMAINS:-}" "${PROXY_ALLOW_IPS:-}" "${PROXY_DENY_IPS:-}" "$metrics_log" &
  proxy_pid=$!
else
  # Metering only: proxy everything
  agent-sandbox-proxy "" "" "" "" "$metrics_log" &
  proxy_pid=$!
fi

# Wait for proxy to signal readiness via the shared volume.
for _ in $(seq 1 50); do
  [[ -f /sidecar_shared/ready ]] && break
  sleep 0.1
done

wait "$proxy_pid"
