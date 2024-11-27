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
        pkgs = import nixpkgs {
            inherit system;
            # TODO: add override to modify Nix
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
            pkgs = nixpkgs.legacyPackages.${system};
            in import ./test.nix {
                makeTest = import (nixpkgs + "/nixos/tests/make-test-python.nix");
                inherit pkgs nix-vsbom;
            };
    });
}
