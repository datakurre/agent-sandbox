#!/usr/bin/env bash
set -euo pipefail

# Graceful shutdown: track background PIDs and forward signals.
tcpdump_pid=""
tinyproxy_pid=""
cleanup() {
  [[ -n "$tcpdump_pid" ]]  && kill "$tcpdump_pid" 2>/dev/null || true
  [[ -n "$tinyproxy_pid" ]] && kill "$tinyproxy_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Rely entirely on Podman's /etc/resolv.conf configuration instead of trying to strip it

if [[ "${METER_NETWORK:-0}" == "1" ]]; then
  tcpdump -U -nni any -w /sidecar_shared/traffic.pcap 2>/sidecar_shared/tcpdump.log &
  tcpdump_pid=$!
fi

if [[ "${FIREWALL:-0}" == "1" && -n "${PROXY_DENY_IPS:-}" ]]; then
  read -ra deny_ips <<< "$PROXY_DENY_IPS"
  for ip in "${deny_ips[@]}"; do
    ip route add blackhole "$ip" || true
  done
fi

# Instead of tinyproxy, run our custom Python proxy which handles "more specific wins"
# for both domains and IPs.
if [[ "${FIREWALL:-0}" == "1" ]]; then
  # Re-construct allow_domains from positional arguments
  allow_domains_csv=""
  if [[ $# -gt 0 ]]; then
    allow_domains_csv="$(IFS=,; echo "$*")"
  fi
  
  agent-sandbox-proxy "$allow_domains_csv" "${PROXY_DENY_DOMAINS:-}" "${PROXY_ALLOW_IPS:-}" "${PROXY_DENY_IPS:-}" &
  tinyproxy_pid=$!
else
  # Metering only: proxy everything
  agent-sandbox-proxy "" "" "" "" &
  tinyproxy_pid=$!
fi

# Wait for proxy to signal readiness via the shared volume.
for _ in $(seq 1 50); do
  [[ -f /sidecar_shared/ready ]] && break
  sleep 0.1
done

wait "$tinyproxy_pid"
