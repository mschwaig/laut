{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    nixpkgs.url = "github:mschwaig/nixpkgs/fix-swig-option-for-souffle-before-rebase";
    bombon.url = "github:nikstur/bombon";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, bombon, flake-utils }@inputs:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-darwin" ] (system:
    let
        nixpkgs-ca = (import nixpkgs { inherit system; }).applyPatches {
          name = "nixpkgs-always-apply-ca";
          src = nixpkgs;
          patches = [
            ./nixpkgs-ca/0001-always-enable-content-addresssing.patch
            ./nixpkgs-ca/0002-always-enable-content-addresssing-for-boostrap-tools.patch
            ];
        };

        pkgs = import nixpkgs {
          inherit system;
        };
        lib = pkgs.lib;
        nix = pkgs.nix;
        nix-vsbom = bombon.lib.${system}.buildBom nix {
          includeBuildtimeDependencies = true;
        };

        test-drv-json = pkgs.writeShellScriptBin "examine-derivation" ''
          nix derivation show --recursive ${nixpkgs-ca}#hello
        '';

        scope = pkgs.callPackage ./default.nix { nixpkgs = null; };
    in {
        packages = {
          inherit nix nix-vsbom test-drv-json;
          default = scope.laut;
        } // scope;


        checks = lib.filterAttrs (name: value:
          # since trust models are not implemented yet
          # it makes no sense to run more than one VM test
          (name == "fullReproVM"))
          (import ./test.nix {
            pkgsCA = nixpkgs-ca;
            pkgsIA = pkgs;
            inherit nixpkgs;
            inherit (scope) laut;
          });

        devShell = let
          pythonEnv = pkgs.python3.withPackages (ps: with ps; [
            rfc8785
            pyjwt
            cryptography
            boto3
            click
            loguru
            sigstore
            pytest
            debugpy
            memory_profiler
          ] ++ [
            pkgs.pyright
          ] ++ [
            nix-verify-souffle
          ]);
        in pkgs.mkShell {
          PYTEST_FOR_VSCODE = "${pythonEnv}/bin/pytest";
          buildInputs = [
            pythonEnv
            pkgs.souffle
            nix-verify-souffle
          ];
        };
    });
}
