{
  description = "Sandboxed AI coding environment via podman";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.antigravity-nix = {
    url = "github:jacopone/antigravity-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.opencode = {
    url = "github:anomalyco/opencode/v2.0.22";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      antigravity-nix,
      opencode,
      ...
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              # claude-code and google-antigravity-cli are unfree.
              config.allowUnfree = true;
              overlays = [
                antigravity-nix.overlays.default
                opencode.overlays.default
                # The pinned upstream release has a stale x86_64-linux
                # node_modules hash. Keep its package definition and sources,
                # correcting only the fixed-output hash for this system. Its
                # CLI also currently fails while generating shell completions.
                (final: prev: {
                  opencode =
                    (prev.opencode.override {
                      node_modules =
                        if final.stdenv.hostPlatform.system == "x86_64-linux" then
                          prev.opencode.node_modules.override {
                            hash = "sha256-g3k0cAFGqzmRYlcIkg1NDvlx1WxHYhnYPL0/a8E+qTg=";
                          }
                        else
                          prev.opencode.node_modules;
                    }).overrideAttrs
                      (_: {
                        postInstall = "";
                      });
                })
              ];
            }
          )
        );

      packageFor = system: self.packages.${system}.default;

    in
    {
      packages = forAllSystems (pkgs: rec {
        default = lib.makeOverridable (import ./default.nix) { inherit pkgs lib; };
        # The image itself, for `nix build .#image` and for shipping it
        # somewhere other than the local podman store.
        image = default.passthru.image;
        # The cooperative host browser, with a pinned Chromium.  Kept out of
        # `default` so a plain install does not carry a browser closure;
        # `agent-sandbox browser` from that install uses a Chromium on PATH.
        browser = default.passthru.browserLauncher;
        # Exposed standalone (agents.nix already wires this into the image) so
        # `nix build .#pi-coding-agent` can verify or update it without a full image
        # rebuild.
        pi-coding-agent = pkgs.callPackage ./pi-coding-agent.nix { };
        # OpenCode from its upstream flake, also used by the bundled agent.
        opencode = pkgs.opencode;
      });

      apps = lib.genAttrs systems (
        system:
        let
          package = packageFor system;
        in
        {
          default = { type = "app"; program = "${package}/bin/agent-sandbox"; meta = { description = "Sandboxed AI coding environment via podman"; }; };
          browser = { type = "app"; program = "${package.passthru.browserLauncher}/bin/agent-sandbox-browser"; meta = { description = "Throwaway host browser behind a deny-by-default allow list"; }; };
        }
      );

      # `nix flake check` builds the Rust workspace, which runs `cargo test`
      # over the launcher, parser and policy suites, without building the
      # container image.
      checks = lib.genAttrs systems (system: (packageFor system).passthru.checks);

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
