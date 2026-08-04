{
  description = "Sandboxed AI coding environment via podman";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.antigravity-nix = {
    url = "github:jacopone/antigravity-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      antigravity-nix,
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
              overlays = [ antigravity-nix.overlays.default ];
            }
          )
        );

      packageFor = system: self.packages.${system}.default;

      app = program: {
        type = "app";
        inherit program;
      };
    in
    {
      packages = forAllSystems (pkgs: rec {
        default = import ./default.nix { inherit pkgs lib; };
        # The image itself, for `nix build .#image` and for shipping it
        # somewhere other than the local podman store.
        image = default.passthru.image;
      });

      apps = lib.genAttrs systems (
        system:
        let
          package = packageFor system;
        in
        {
          default = app "${package}/bin/agent-sandbox";
          load = app "${package}/bin/agent-sandbox-load";
          port = app "${package}/bin/agent-sandbox-port";
          purge = app "${package}/bin/agent-sandbox-purge";
        }
      );

      # `nix flake check` runs the parser and gnupg-classifier test suites and
      # shellchecks every script, without building the container image.
      checks = lib.genAttrs systems (system: (packageFor system).passthru.checks);

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
