{
  description = "Sandboxed AI coding environment via podman";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.antigravity-nix = {
    url = "github:jacopone/antigravity-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, antigravity-nix, ... }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      packages = builtins.listToAttrs (
        map
          (system: {
            name = system;
            value = {
              default = import ./default.nix {
                pkgs = import nixpkgs {
                  inherit system;
                  config.allowUnfree = true;
                  overlays = [ antigravity-nix.overlays.default ];
                };
                inherit lib;
              };
            };
          })
          systems
      );

      apps = builtins.listToAttrs (
        map
          (system: {
            name = system;
            value.default = {
              type = "app";
              program = "${self.packages.${system}.default}/bin/agent-sandbox";
            };
          })
          systems
      );

      overlays.default = _final: _prev: { };
    };
}
