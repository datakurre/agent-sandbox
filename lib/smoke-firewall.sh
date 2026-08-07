#!/usr/bin/env bash
# Hand-run smoke test for the firewall, against real containers.
#
# Everything here needs a working rootless podman and network egress, so it
# cannot be a nix check -- `nix flake check` covers the policy round-trip, the
# argument handling and the proxy's own logic, but nothing that actually starts a
# container.  This script is the written procedure for the rest.
#
# Usage:  bash lib/smoke-firewall.sh
#
# Assumes `agent-sandbox` and `agent-sandbox-ctl` are on PATH and the image is
# loaded (agent-sandbox-ctl load).

set -uo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; podman rm -f "$sandbox" >/dev/null 2>&1' EXIT
sandbox=""

failures=0
pass() { printf 'ok       %s\n' "$1"; }
fail() { printf 'FAIL     %s\n' "$1"; printf '%s\n' "${2:-}" | sed 's/^/           /'; failures=$((failures + 1)); }

# Two entries in every list: one entry works even with a broken handoff, which is
# exactly how the separator bug survived for so long.
mkdir -p "$tmp/work"
cat > "$tmp/work/AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domains = ["example.com", "*.example.com"]
deny_domains = ["blocked.example.org", "also-blocked.example.org"]
allow_ips = ["10.0.0.0/8", "192.168.0.0/16"]
deny_ips = ["203.0.113.0/24", "198.51.100.7"]
```
EOF

echo "=== launching a --firewall sandbox in $tmp/work ==="
cd "$tmp/work" || exit 1

# Background, so the checks can run against it; the launcher stays in the
# foreground of its own shell.
agent-sandbox --firewall --no-workspace -- sleep 600 >"$tmp/launch.log" 2>&1 &
launcher=$!

for _ in $(seq 1 60); do
  sandbox=$(podman ps --filter "label=agent-sandbox.role=sandbox" --format '{{.Names}}' | head -n 1)
  [[ -n "$sandbox" ]] && break
  kill -0 "$launcher" 2>/dev/null || break
  sleep 1
done

if [[ -z "$sandbox" ]]; then
  fail "the sandbox started" "$(cat "$tmp/launch.log")"
  exit 1
fi
pass "the sandbox started ($sandbox)"

# ── the policy actually reached the proxy ────────────────────────────────────

rules=$(agent-sandbox-ctl firewall show --sandbox "$sandbox")
for want in \
  "example.com" "*.example.com" \
  "blocked.example.org" "also-blocked.example.org" \
  "10.0.0.0/8" "192.168.0.0/16" \
  "203.0.113.0/24" "198.51.100.7"
do
  if grep -qF -- "$want" <<< "$rules"; then
    pass "policy carries $want"
  else
    fail "policy carries $want" "$rules"
  fi
done

if grep -q "default *deny" <<< "$rules"; then
  pass "an allow list means deny by default"
else
  fail "an allow list means deny by default" "$rules"
fi

# ── enforcement ──────────────────────────────────────────────────────────────

in_sandbox() { podman exec "$sandbox" "$@"; }

if in_sandbox curl -sS -o /dev/null -m 20 https://example.com; then
  pass "an allowed host is reachable"
else
  fail "an allowed host is reachable" "$(agent-sandbox-ctl logs --sandbox "$sandbox" | tail -5)"
fi

if in_sandbox curl -sS -o /dev/null -m 20 https://nixos.org 2>/dev/null; then
  fail "a host outside the allow list is refused" "nixos.org was reachable"
else
  pass "a host outside the allow list is refused"
fi

# The second deny_ips entry is a bare address, which used to be dropped on the
# floor by the proxy while the parser accepted it.
if in_sandbox getent hosts 198.51.100.7 >/dev/null 2>&1; then :; fi
if in_sandbox curl -sS -o /dev/null -m 10 http://198.51.100.7 2>/dev/null; then
  fail "a denied bare address is refused" "198.51.100.7 was reachable"
else
  pass "a denied bare address is refused"
fi

# ── runtime policy change ────────────────────────────────────────────────────

agent-sandbox-ctl firewall allow --sandbox "$sandbox" nixos.org >/dev/null
sleep 2   # the proxy polls the policy once a second

if in_sandbox curl -sS -o /dev/null -m 20 https://nixos.org; then
  pass "firewall allow takes effect without a restart"
else
  fail "firewall allow takes effect without a restart" \
    "$(agent-sandbox-ctl logs --sandbox "$sandbox" | tail -8)"
fi

agent-sandbox-ctl firewall rm --sandbox "$sandbox" nixos.org >/dev/null
sleep 2
if in_sandbox curl -sS -o /dev/null -m 20 https://nixos.org 2>/dev/null; then
  fail "firewall rm takes effect without a restart" "nixos.org still reachable"
else
  pass "firewall rm takes effect without a restart"
fi

# ── the sandbox cannot reach the policy or the log ───────────────────────────

if in_sandbox test -e /sidecar_policy 2>/dev/null; then
  fail "the policy is not visible inside the sandbox" "/sidecar_policy exists"
else
  pass "the policy is not visible inside the sandbox"
fi
if in_sandbox test -e /sidecar_shared 2>/dev/null; then
  fail "the connection log is not visible inside the sandbox" "/sidecar_shared exists"
else
  pass "the connection log is not visible inside the sandbox"
fi

# ── the visibility commands work against a live sandbox ──────────────────────

for cmd in status net logs; do
  if agent-sandbox-ctl "$cmd" --sandbox "$sandbox" >/dev/null 2>"$tmp/err"; then
    pass "ctl $cmd works"
  else
    fail "ctl $cmd works" "$(cat "$tmp/err")"
  fi
done

if agent-sandbox-ctl port add --sandbox "$sandbox" 18080 2>"$tmp/err"; then
  fail "port add refuses a firewalled sandbox" "it succeeded"
else
  if grep -q "does not pass through the proxy" "$tmp/err"; then
    pass "port add refuses a firewalled sandbox"
  else
    fail "port add refuses a firewalled sandbox" "$(cat "$tmp/err")"
  fi
fi

# ── refusals at launch ───────────────────────────────────────────────────────

if agent-sandbox --firewall --port 18081 --no-workspace -- true >"$tmp/err" 2>&1; then
  fail "--firewall with a port is refused" "it launched"
else
  if grep -q "cannot be combined" "$tmp/err"; then
    pass "--firewall with a port is refused"
  else
    fail "--firewall with a port is refused" "$(cat "$tmp/err")"
  fi
fi

mkdir -p "$tmp/bad"
cat > "$tmp/bad/AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domians = ["example.com"]
```
EOF
if (cd "$tmp/bad" && agent-sandbox --firewall --no-workspace -- true >"$tmp/err" 2>&1); then
  fail "a misspelled [proxy] key refuses the launch" "it launched"
else
  if grep -q "invalid \[proxy\] block" "$tmp/err"; then
    pass "a misspelled [proxy] key refuses the launch"
  else
    fail "a misspelled [proxy] key refuses the launch" "$(cat "$tmp/err")"
  fi
fi

# ── teardown leaves nothing behind ───────────────────────────────────────────

podman rm -f "$sandbox" >/dev/null 2>&1
wait "$launcher" 2>/dev/null
sandbox=""

leftover_nets=$(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' | wc -l)
if [[ "$leftover_nets" -eq 0 ]]; then
  pass "no session network is leaked"
else
  fail "no session network is leaked" "$leftover_nets left; agent-sandbox-ctl purge reclaims them"
fi

leftover_dirs=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'agent-sandbox-policy-*' 2>/dev/null | wc -l)
if [[ "$leftover_dirs" -eq 0 ]]; then
  pass "no policy directory is leaked"
else
  fail "no policy directory is leaked" "$leftover_dirs left"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s check(s) failed\n' "$failures" >&2
  exit 1
fi
printf '\nall firewall smoke checks passed\n'
