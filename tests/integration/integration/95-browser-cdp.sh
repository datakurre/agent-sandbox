#!/usr/bin/env bash
# `--browser` carries CDP from inside the sandbox to a browser on the host.
#
# 90-browser-ports tests the browser's proxy and never connects a sandbox to
# the browser; 70-host-loopback-port tests the bridge with a plain service.
# This is the case in between, and the one an enforcing SELinux host broke: a
# sandbox started with `--browser` fetches the browser's DevTools endpoint
# through the host-loopback bridge, with and without `--proxy`. It also checks
# that the managed-policy layer was applied, which needs bwrap's overlay on
# the host and cannot be tested from inside a container.
#
# The browser is a stand-in that serves a stub /json/version on the port
# `agent-sandbox browser` gave it, so no display and no Chromium are needed.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_command curl
require_command python3

ws="$(make_workspace)"
name="astest-cdp-$$"
rt="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agent-sandbox-browser-$name"

# Takes the two flags a real Chromium would act on: the CDP port to listen on
# and the profile directory, which the browser removes again on exit.
cat > "$ws/fake-chromium" <<'EOF'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    --remote-debugging-port=*) port="${arg#*=}" ;;
    --user-data-dir=*) profile="${arg#*=}" ;;
  esac
done
mkdir -p "$profile/json"
echo '{"Browser":"astest-fake-cdp"}' > "$profile/json/version"
cd "$profile" && exec python3 -m http.server "$port" --bind 127.0.0.1
EOF
chmod +x "$ws/fake-chromium"

# Out of the repository, so its AGENTS.md does not seed the allow list.
cd "$ws" || exit 1

cleanup() {
  stop_bg "${browser:-}"
  rm -rf "$ws"
  cleanup_sandboxes
}
trap cleanup EXIT

"$AS" ctl browser --name "$name" --no-extensions --chromium "$ws/fake-chromium" \
  >"$ws/browser.log" 2>&1 &
browser=$!

for _ in $(seq 1 40); do
  [ -f "$rt/meta.json" ] && break
  sleep 0.5
done
[ -f "$rt/meta.json" ] || _fail "the browser never wrote $rt/meta.json ($(cat "$ws/browser.log"))"

cdp="$(grep -o '"cdp_port"[^0-9]*[0-9]*' "$rt/meta.json" | grep -o '[0-9]*$')"
[ -n "$cdp" ] || _fail "no CDP port in $rt/meta.json"

for _ in $(seq 1 30); do
  curl --silent --max-time 2 -o /dev/null "http://127.0.0.1:$cdp/json/version" && break
  sleep 0.5
done
host="$(curl --silent --max-time 5 "http://127.0.0.1:$cdp/json/version" || true)"
assert_contains "$host" "astest-fake-cdp" "the stand-in browser on the host"

# ── the managed-policy layer ────────────────────────────────────────────────

if command -v bwrap >/dev/null 2>&1; then
  assert_not_contains "$(cat "$ws/browser.log")" "no managed-policy layer" \
    "the browser's log, with bwrap on PATH"
else
  pass_note "bwrap is not on PATH; the managed-policy layer was not tested"
fi

# ── CDP from inside ─────────────────────────────────────────────────────────

probe='echo "port=$AGENT_SANDBOX_BROWSER_CDP_PORT"; curl --silent --max-time 5 "http://127.0.0.1:$AGENT_SANDBOX_BROWSER_CDP_PORT/json/version" || echo failed'

out="$(sandbox_run --browser="$name" -- bash -c "$probe")"
assert_contains "$out" "port=$cdp" "the CDP port advertised inside"
assert_contains "$out" "astest-fake-cdp" "the browser's DevTools endpoint, fetched from inside"

# The bridge is a unix socket, not a route, so the proxy's network does not
# change it; NO_PROXY keeps the fetch off the proxy.
out="$(sandbox_run --proxy --browser="$name" -- bash -c "$probe")"
assert_contains "$out" "astest-fake-cdp" "the same endpoint under --proxy"

stop_bg "$browser"
exit 0
