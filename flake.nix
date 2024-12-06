{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # TODO: modify bombon
    bombon.url = "github:nikstur/bombon";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, bombon, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ]  (system:
    let
        contentAddressedOverlay = final: prev: {
          config = prev.config // {
            contentAddressedByDefault = true;
          };
        };
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ contentAddressedOverlay ];
#          config.contentAddressedByDefault = true;
        };
        nix = pkgs.nix;
        nix-vsbom = bombon.lib.${system}.buildBom nix {
          includeBuildtimeDependencies = true;
        };
    in {
        packages = {
          inherit nix nix-vsbom;
        };

        checks = let
            system = "x86_64-linux";
            # pkgs = nixpkgs.legacyPackages.${system};
            in import ./test.nix {
                inherit pkgs nix-vsbom;
            };
    });
}
