#!/usr/bin/env bash
set -euo pipefail

domain="${1:-}"
if [[ -z "$domain" ]]; then
  echo "Usage: agent-sandbox-allow <domain>" >&2
  exit 1
fi

if [[ ! -f "/sidecar_shared/allowed_domains" ]]; then
  echo "Error: Proxy firewall is not active." >&2
  exit 1
fi

# Build the same anchored regex pattern as agent-sandbox-sidecar.
if [[ "$domain" == \*.* ]]; then
  rest="${domain#\*.}"
  rest="${rest//./\\.}"
  pattern="^.*\\.${rest}$"
else
  escaped="${domain//./\\.}"
  pattern="^${escaped}$"
fi

# Don't add duplicates.
if ! grep -qxF "$pattern" /sidecar_shared/allowed_domains 2>/dev/null; then
  printf '%s\n' "$pattern" >> /sidecar_shared/allowed_domains
fi
echo "Allowed domain: $domain"
