#!/usr/bin/env bash
# --host-loopback-port under --krun.
#
# Under krun the bind mount carrying the bridge's sockets is virtiofs, and
# whether a unix socket the guest listens on there can be dialled from the
# host is a property of libkrun, not of this code. 70-host-loopback-port
# covers the ordinary runtime; this is the same round trip inside a microVM.
#
# `--nix` rides the same bridge, so its outcome is printed for the log but not
# asserted until the plain mapping is known to work.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_command curl

out="$(sandbox_run --krun -- true)" \
  || skip "--krun does not launch on this host: $out"

hostport=18124
require_free_port "$hostport"
server="$(start_host_http_server "$hostport" 127.0.0.1)" \
  || skip "no way to start an HTTP server on the host (no python3, no nix)"
trap 'kill $server 2>/dev/null; cleanup_sandboxes' EXIT

for _ in $(seq 1 30); do
  curl --silent --max-time 2 -o /dev/null "http://127.0.0.1:$hostport/" && break
  sleep 1
done

out="$(sandbox_run --krun --host-loopback-port "$hostport" -- \
  bash -c "curl --silent --max-time 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:$hostport/ || echo failed")"
assert_not_contains "$out" "could not forward host port" "the bridge's startup report"
assert_contains "$out" "200" "a host loopback service, fetched from inside a krun guest"

out="$(sandbox_run --krun --nix -- true)"
case "$out" in
  *"continuing without the host Nix cache"*)
    echo "  note: --nix under --krun did not reach the host cache:"
    echo "$out" | grep -- '--nix' | sed 's/^/    /' ;;
  *) echo "  note: --nix under --krun reached the host cache" ;;
esac
