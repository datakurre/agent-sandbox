#!/usr/bin/env bash
# An [[network.allowed_routes]] rule narrows a host to specific requests.
#
# Enforcing this means terminating TLS on the session CA, so the case also
# checks the two halves that make that safe: the sandbox trusts the CA only
# when a rule needs it, and a denied request is denied after decryption rather
# than before the policy could see it.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

# example.com rather than httpbin.org: this case has to distinguish "the proxy
# refused" from "the origin was flaky", and httpbin is famously the latter.
# example.com serves / and 404s everything else, both from a stable host.
cat > AGENTS.md <<'EOF'
# L7 test

```toml agent-sandbox
[[network.allowed_routes]]
host = "example.com"
method = "GET"
path = "/"
```
EOF

code='curl --silent --show-error --max-time 20 -o /dev/null -w "%{http_code}"'

out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/ || echo BLOCKED")"
assert_contains "$out" "200" "the method and path the route allows"

# A different path on the same host. The origin would answer 404; the proxy
# must not let the request reach it at all.
out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/admin || echo BLOCKED")"
assert_denied "$out" "a path the route does not cover"

out="$(sandbox_run --workspace --proxy -- \
  bash -c "$code -X POST https://example.com/ || echo BLOCKED")"
assert_denied "$out" "a method the route does not allow"

# The CA is handed over only because this policy has an L7 rule.
out="$(sandbox_run --workspace --proxy -- bash -c 'ls /run/agent-sandbox-proxy-ca.pem 2>&1 || echo ABSENT')"
assert_contains "$out" "/run/agent-sandbox-proxy-ca.pem" "the session CA under an L7 policy"

# The same route written as one allowed_hosts entry, restricted to port 443:
# the unit tests can only check the policy file it compiles to, not that the
# proxy enforces it.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["GET example.com:443/"]
```
EOF

out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/ || echo BLOCKED")"
assert_contains "$out" "200" "the method and path a short-form route allows"

out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/admin || echo BLOCKED")"
assert_denied "$out" "a path the short-form route does not cover"

out="$(sandbox_run --workspace --proxy -- \
  bash -c "$code -X POST https://example.com/ || echo BLOCKED")"
assert_denied "$out" "a method the short-form route does not allow"

# Unlike the table above, which names no port, this entry names 443 alone, so
# the route must not have widened the host to plain HTTP. Refused before the
# origin is contacted, so the answer cannot be the origin's.
out="$(sandbox_run --workspace --proxy -- bash -c "$code http://example.com/ || echo BLOCKED")"
assert_denied "$out" "a port the short-form route does not name"

out="$(sandbox_run --workspace --proxy -- bash -c 'ls /run/agent-sandbox-proxy-ca.pem 2>&1 || echo ABSENT')"
assert_contains "$out" "/run/agent-sandbox-proxy-ca.pem" "the session CA under a short-form route"

# With no L7 rule there is nothing to intercept, so no CA should be trusted:
# a CA that can mint any name is not something to hand over for free.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF
out="$(sandbox_run --workspace --proxy -- bash -c 'ls /run/agent-sandbox-proxy-ca.pem 2>&1 || echo ABSENT')"
assert_contains "$out" "ABSENT" "the session CA under an L4-only policy"

# ...and an L4 rule for the same host still passes traffic through untouched.
out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/ || echo BLOCKED")"
assert_contains "$out" "200" "an L4-allowed host with no interception"

# The proxy originates its own TLS to the origin, and some origins still stop
# at TLS 1.2: registry.npmjs.org answers a 1.3-only ClientHello with a
# protocol_version alert, which the sandbox client sees as a dropped connection.
cat > AGENTS.md <<'EOF2'
```toml agent-sandbox
[[network.allowed_routes]]
host = "registry.npmjs.org"
method = "GET"
path = "/**"
```
EOF2
out="$(sandbox_run --workspace --proxy -- bash -c "$code https://registry.npmjs.org/-/ping || echo BLOCKED")"
assert_contains "$out" "200" "an intercepted origin that negotiates TLS 1.2"
