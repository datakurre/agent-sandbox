#!/usr/bin/env bash
# Round-trip tests for the firewall policy: AGENTS.md -> policy file -> proxy,
# and policy file -> sidecar blackhole routes.
#
# This is the hop that had no coverage, and it is where the fail-open bug lived:
# the launcher handed the lists over space-separated while the proxy split them on
# commas, so everything past the first entry was silently dropped -- and an
# emptied allow list means allowing everything.  Every list in the fixture below
# therefore carries TWO entries: a one-entry fixture cannot tell a working
# handoff from a broken one.
#
# Usage: test-firewall-policy.sh PARSER PROXY SIDECAR_SCRIPT

set -euo pipefail

parser="${1:?usage: test-firewall-policy.sh PARSER PROXY SIDECAR_SCRIPT}"
proxy="${2:?}"
sidecar="${3:?}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0

pass() { printf 'ok       %s\n' "$1"; }
fail() {
  printf 'FAIL     %s\n' "$1"
  printf '%s\n' "${2:-}" > "$tmp/msg"
  sed 's/^/           /' "$tmp/msg"
  failures=$((failures + 1))
}

expect_contains() {
  local label="$1" want="$2" have="$3"
  if grep -qF -- "$want" <<< "$have"; then
    pass "$label"
  else
    fail "$label" "missing: $want"$'\n'"$have"
  fi
}

# ── the fixture ─────────────────────────────────────────────────────────────

cat > "$tmp/AGENTS.md" <<'EOF'
# Project

```toml agent-sandbox
[proxy]
allow_domains = ["github.com", "*.githubusercontent.com"]
deny_domains = ["telemetry.example.com", "ads.example.com"]
allow_ips = ["10.0.0.0/8", "192.168.1.0/24"]
deny_ips = ["10.1.0.0/24", "8.8.8.8"]
```
EOF

# ── 1. the parser emits one entry per line ──────────────────────────────────

policy=$("$parser" --proxy-policy "$tmp/AGENTS.md")
printf '%s\n' "$policy" > "$tmp/policy"

expected='allow_domains github.com
allow_domains *.githubusercontent.com
deny_domains telemetry.example.com
deny_domains ads.example.com
allow_ips 10.0.0.0/8
allow_ips 192.168.1.0/24
deny_ips 10.1.0.0/24
deny_ips 8.8.8.8'

if [[ "$(grep -v '^#' <<< "$policy")" == "$expected" ]]; then
  pass "parser emits one entry per line"
else
  fail "parser emits one entry per line" "$policy"
fi

# ── 2. the proxy reads back every entry ─────────────────────────────────────
# The regression test.  Against the old comma-splitting code the two-entry IP
# lists came back empty, and with allow_ips empty the policy became allow-all.

rules=$("$proxy" --check-policy "$tmp/policy")

for want in \
  "allow_domains github.com" \
  "allow_domains *.githubusercontent.com" \
  "deny_domains telemetry.example.com" \
  "deny_domains ads.example.com" \
  "allow_ips 10.0.0.0/8" \
  "allow_ips 192.168.1.0/24" \
  "deny_ips 10.1.0.0/24" \
  "deny_ips 8.8.8.8"
do
  expect_contains "proxy keeps '$want'" "$want" "$rules"
done

expect_contains "an allow list means deny by default" "default deny" "$rules"

# ── 3. the old wire format is now a hard error ──────────────────────────────

printf 'allow_ips 10.0.0.0/8 192.168.1.0/24\n' > "$tmp/spaced"
if "$proxy" --check-policy "$tmp/spaced" > "$tmp/out" 2>&1; then
  fail "the old space-separated encoding is rejected" "$(cat "$tmp/out")"
else
  status=$?
  if [[ "$status" == 2 ]]; then
    pass "the old space-separated encoding is rejected"
  else
    fail "the old space-separated encoding is rejected" "exit $status, wanted 2"
  fi
  expect_contains "and the error names the problem" "whitespace" "$(cat "$tmp/out")"
fi

# ── 4. other malformed policies fail closed ─────────────────────────────────

check_rejects() {
  local label="$1" body="$2"
  printf '%s\n' "$body" > "$tmp/bad"
  if "$proxy" --check-policy "$tmp/bad" >/dev/null 2>&1; then
    fail "$label" "accepted: $body"
  else
    pass "$label"
  fi
}

check_rejects "an unknown key is rejected"      "allow_domians github.com"
check_rejects "a bad CIDR is rejected"          "allow_ips not-an-ip"
check_rejects "a bad default is rejected"       "default maybe"
check_rejects "a valueless key is rejected"     "allow_domains"

if "$proxy" --check-policy "$tmp/nonexistent" >/dev/null 2>&1; then
  fail "a missing policy file is rejected" "accepted a nonexistent path"
else
  pass "a missing policy file is rejected"
fi

# ── 5. a malformed [proxy] block refuses to produce a policy ────────────────
# The launcher relies on this exit status; it used to discard it, which turned a
# typo in AGENTS.md into a firewall that allowed everything.

cat > "$tmp/bad-AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_ips = ["not-an-ip"]
```
EOF
if "$parser" --proxy-policy "$tmp/bad-AGENTS.md" >/dev/null 2>&1; then
  fail "an invalid [proxy] block exits non-zero" "accepted an invalid CIDR"
else
  pass "an invalid [proxy] block exits non-zero"
fi

cat > "$tmp/typo-AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domians = ["github.com"]
```
EOF
if "$parser" --proxy-policy "$tmp/typo-AGENTS.md" >/dev/null 2>&1; then
  fail "a misspelled [proxy] key exits non-zero" "accepted allow_domians"
else
  pass "a misspelled [proxy] key exits non-zero"
fi

# ── 6. the sidecar derives one blackhole route per deny_ips entry ────────────
# Same class of bug on the kernel-route side: these used to come from a
# space-separated env var that only worked by accident for a single entry.

dry=$(FIREWALL=1 \
      AGENT_SANDBOX_SIDECAR_DRY_RUN=1 \
      AGENT_SANDBOX_SIDECAR_POLICY="$tmp/policy" \
      bash "$sidecar")

routes=$(grep -c 'route add blackhole' <<< "$dry" || true)
if [[ "$routes" == 2 ]]; then
  pass "one blackhole route per deny_ips entry"
else
  fail "one blackhole route per deny_ips entry" "found $routes"$'\n'"$dry"
fi
expect_contains "blackhole covers the first entry"  "blackhole 10.1.0.0/24" "$dry"
expect_contains "blackhole covers the second entry" "blackhole 8.8.8.8"     "$dry"
expect_contains "the proxy is given the policy file" "--policy" "$dry"

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s test(s) failed\n' "$failures" >&2
  exit 1
fi

printf '\nall firewall-policy tests passed\n'
