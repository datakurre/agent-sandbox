#!/usr/bin/env bash
# --host-loopback-port is refused under --krun.
#
# The bridge needs the host to dial a unix socket the guest listens on over
# virtiofs, and a krun guest's socket never reaches the host: the guest accepts
# the client and no host connection arrives.  Until there is another transport,
# the launcher says so up front instead of leaving a port that silently hangs.
# The refusal happens before any container starts, so this needs no krun.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

out="$(sandbox_run --krun --host-loopback-port 18124 -- true)"
assert_contains "$out" "cannot be used with --krun" "--host-loopback-port under --krun"

out="$(sandbox_run --krun --nix -- true)"
case "$out" in
  *"continuing without the host Nix cache"*)
    echo "  note: --nix under --krun did not reach the host cache:"
    echo "$out" | grep -- '--nix' | sed 's/^/    /' ;;
  *) echo "  note: --nix under --krun reached the host cache" ;;
esac
