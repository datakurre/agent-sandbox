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

# Force DNS resolution to use the default route's gateway (the external network),
# ignoring the internal network's DNS server which drops external queries.
DEFAULT_GW_HEX=$(awk '$2 == 00000000 {print $3}' /proc/net/route | head -n1)
if [[ -n "$DEFAULT_GW_HEX" ]]; then
  GW_IP=$(( 0x${DEFAULT_GW_HEX:6:2} )).$(( 0x${DEFAULT_GW_HEX:4:2} )).$(( 0x${DEFAULT_GW_HEX:2:2} )).$(( 0x${DEFAULT_GW_HEX:0:2} ))
  echo "nameserver $GW_IP" > /tmp/resolv.conf
  cat /tmp/resolv.conf > /etc/resolv.conf
fi

if [[ "${METER_NETWORK:-0}" == "1" ]]; then
  tcpdump -nni any -w /sidecar_shared/traffic.pcap >/dev/null 2>&1 &
  tcpdump_pid=$!
fi

# Convert a domain (optionally wildcard) into an anchored regex for tinyproxy.
#   github.com     → ^github\.com$
#   *.github.com   → ^.*\.github\.com$
escape_domain() {
  local d="$1"
  if [[ "$d" == \*.* ]]; then
    local rest="${d#\*.}"
    rest="${rest//./\\.}"
    printf '%s\n' "^.*\\.${rest}$"
  else
    d="${d//./\\.}"
    printf '%s\n' "^${d}$"
  fi
}

if [[ "${FIREWALL:-0}" == "1" ]]; then
  # Write anchored regex patterns.  An empty arg list → empty file (deny all).
  if [[ $# -gt 0 ]]; then
    for domain in "$@"; do
      escape_domain "$domain"
    done > /sidecar_shared/allowed_domains
  else
    : > /sidecar_shared/allowed_domains
  fi
  cat <<EOF > /tmp/tinyproxy.conf
Port 8888
Allow 0.0.0.0/0
ConnectPort 443
ConnectPort 80
Filter "/sidecar_shared/allowed_domains"
FilterDefaultDeny Yes
FilterExtended On
FilterURLs Off
EOF
else
  # Metering only: proxy everything.
  cat <<EOF > /tmp/tinyproxy.conf
Port 8888
Allow 0.0.0.0/0
ConnectPort 443
ConnectPort 80
EOF
fi

# Run tinyproxy in foreground mode (-d) so we can track its PID.
tinyproxy -d -c /tmp/tinyproxy.conf &
tinyproxy_pid=$!

# Watch for filter updates if firewall is active; otherwise just wait.
if [[ "${FIREWALL:-0}" == "1" ]]; then
  while kill -0 "$tinyproxy_pid" 2>/dev/null; do
    inotifywait -e close_write /sidecar_shared/allowed_domains >/dev/null 2>&1 || { sleep 1; continue; }
    kill -HUP "$tinyproxy_pid" 2>/dev/null || true
  done
else
  wait "$tinyproxy_pid"
fi
