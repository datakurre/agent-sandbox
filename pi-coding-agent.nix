# Bakes `pi` into the image the same way every other agent already is (see agents.nix),
# instead of `agents.nix`'s previous shim -- `writeShellScriptBin "pi" "exec npx -y
# @earendil-works/pi-coding-agent \"$@\""` -- which fetched the whole dependency tree
# from registry.npmjs.org on *every* container launch. That both defeats the sandbox's
# offline/deny-by-default posture for a basic feature and is a live launch-time failure
# mode: registry.npmjs.org returning a transient error (a 403, seen in practice) breaks
# `pi` entirely until the next successful fetch. Building it as a real Nix derivation
# fetches once, at image-build time, and every container launch afterward needs no
# npm/network access to start `pi` at all.
{
  lib,
  buildNpmPackage,
  fetchzip,
}:

buildNpmPackage rec {
  pname = "pi-coding-agent";
  version = "0.84.2";

  src = fetchzip {
    url = "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-${version}.tgz";
    # NAR hash of the unpacked, stripRoot'd tree -- not npm's own `dist.integrity`
    # (which is over the raw .tgz bytes, a different thing `fetchzip` doesn't expose).
    hash = "sha512-OS4T61OnyhNO82C4n11F+dT/2+DrH/P7kLW32MOD5wIZSo0hjpVF/znzaN9KPHwk6fV8hojVv+T2Oyg0T5KYxw==";
  };

  # Two independent fixups to the published sources, both needed before `npm ci` can
  # succeed fully offline against the prefetched dependency cache. `sed`, not `jq`, for
  # both: this patch also has to run inside `fetchNpmDeps`'s own fixed-output derivation
  # (buildNpmPackage forwards postPatch there so the deps fetch sees the same sources the
  # main build does), whose minimal builder doesn't carry `nativeBuildInputs` from the
  # outer package -- only base stdenv tools are guaranteed there.
  postPatch = ''
    # The published npm-shrinkwrap.json is prod-only (no devDependencies entries at all
    # -- verified: `@types/cross-spawn` etc. appear in package.json's devDependencies but
    # nowhere in the shrinkwrap), but package.json itself still lists devDependencies. npm
    # resolves against package.json regardless of `--omit=dev`, so left alone it reaches
    # for a package the offline cache (built from the shrinkwrap) was never going to have
    # and fails outright rather than skipping it. Dropped here since nothing here needs to
    # build or test the package, only install and run its prebuilt dist/.
    sed -i '/^\t"devDependencies": {$/,/^\t},$/d' package.json
    # The sed anchors on the published file's tab indentation and on the block not
    # being the last key (deleting it must not orphan the previous line's comma). A
    # reformat upstream would make it a silent no-op, so assert the postcondition.
    if grep -q '"devDependencies"' package.json; then
      echo "pi-coding-agent: devDependencies survived the sed above -- its anchors are stale" >&2
      exit 1
    fi

    # The shrinkwrap carries `integrity` for every third-party dependency except its six
    # sibling `@earendil-works/pi-*` packages -- an artifact of how the monorepo's own
    # shrinkwrap-generation script resolves workspace-internal packages, not something
    # wrong with the packages themselves. `prefetch-npm-deps` (and so `buildNpmPackage`'s
    # `npmDepsHash`) refuses to trust a download it can't verify, so `npmDepsHash` can't
    # be computed from the file as published without this patch. Each hash below is that
    # package's own `dist.integrity` as published (confirmed against a from-scratch
    # sha512 of the downloaded tarball, not copied on trust) -- one `resolved` line per
    # package is a unique anchor to insert its `integrity` line after. Re-verify with
    # `npm view @earendil-works/pi-<name>@${version} dist.integrity` if bumping `version`
    # ever fails prefetch again.
    sed -i \
      -e '\#"resolved": "https://registry.npmjs.org/@earendil-works/pi-agent-core/-/pi-agent-core-${version}.tgz"#a\      "integrity": "sha512-8Pn3wSCxj0cfo5I6jxQYVB/3uuQRmHhAlEclyjqpOuMEdQMIODHizRogv56FLdbU+dTiGnybeHQ2N+sV1/L2YA==",' \
      -e '\#"resolved": "https://registry.npmjs.org/@earendil-works/pi-ai/-/pi-ai-${version}.tgz"#a\      "integrity": "sha512-6MzsrYIYNVlE7SfpbL2yYb67Qo58p/7Q+xWG1RZvoX1P80aRCHSod2/13aFpxkow1lPO2LEh3c495J0Gwmyjig==",' \
      -e '\#"resolved": "https://registry.npmjs.org/@earendil-works/pi-client/-/pi-client-${version}.tgz"#a\      "integrity": "sha512-/RFSPhD/bZbpOp1oJj+UneSUFSgZhWxzcSENUY+8+8xhoBrWXMYI2t77XNx4Yf+c8YK2qTHquForhNcelYpXvg==",' \
      -e '\#"resolved": "https://registry.npmjs.org/@earendil-works/pi-protocol/-/pi-protocol-${version}.tgz"#a\      "integrity": "sha512-jbBh03fkeckWEroHpcZBr4w5/Ibat8WwdXFlXHivYQImrQNFtLpDeL0t1cku4hmK0q3pceIRQHkw4fwbM4YILQ==",' \
      -e '\#"resolved": "https://registry.npmjs.org/@earendil-works/pi-telemetry/-/pi-telemetry-${version}.tgz"#a\      "integrity": "sha512-wg5caea7uIv1BHRBm2Y116RvFG4oSAiP5qk9tA2463PDGIr4K8M1Ceyyg5DOpF/shUUl0gk826yQJAeAcHYB9g==",' \
      -e '\#"resolved": "https://registry.npmjs.org/@earendil-works/pi-tui/-/pi-tui-${version}.tgz"#a\      "integrity": "sha512-ds2TLihOnM5sLJB3VpXV6y0uR5efVuHf4MN7yDpsty6hA2DUO/EDVzjp/0od0G2JslzVLMjT8T8zavtxVb+qbg==",' \
      npm-shrinkwrap.json

    # A `sed` whose anchor no longer matches is not an error, so a version bump would
    # silently leave these entries unpatched and surface as an opaque `npmDepsHash`
    # mismatch. Fail here instead, where the cause is legible.
    for pkg in pi-agent-core pi-ai pi-client pi-protocol pi-telemetry pi-tui; do
      grep -A1 "/$pkg/-/$pkg-${version}.tgz" npm-shrinkwrap.json | grep -q '"integrity"' \
        || { echo "pi-coding-agent: no integrity line for @earendil-works/$pkg@${version}; re-check the hashes above with 'npm view @earendil-works/$pkg@${version} dist.integrity'" >&2; exit 1; }
    done
  '';

  npmDepsHash = "sha256-JwFYcknXfOvSWvqUFYSGy0HefAV2xdm+XTJYntMnzd8=";

  # dist/ ships prebuilt in the published tarball (see package.json's `prepublishOnly`
  # in the pi monorepo) -- there is no TypeScript source in this tarball to compile.
  dontNpmBuild = true;

  meta = {
    description = "Pi coding agent CLI (read/bash/edit/write tools, session management)";
    homepage = "https://github.com/earendil-works/pi";
    license = lib.licenses.mit;
    mainProgram = "pi";
  };
}
