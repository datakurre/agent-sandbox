#!/usr/bin/env bash
# Build the image and import it into the host's podman image store.
#
# streamLayeredImage writes the tar to stdout instead of materialising a
# multi-gigabyte tarball in the nix store first, so this pipes straight into
# podman load.

echo "Loading $AGENT_SANDBOX_IMAGE into podman..."
"$AGENT_SANDBOX_IMAGE_STREAM" | podman load
echo "Done. Run 'agent-sandbox' to start a session."
