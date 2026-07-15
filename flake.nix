{
  description = "Sandboxed AI coding environment via podman";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs, ... }:
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
                pkgs = nixpkgs.legacyPackages.${system};
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
