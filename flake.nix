{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    bombon.url = "github:nikstur/bombon";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, bombon, flake-utils }@inputs:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-darwin" ] (system:
    let
        pkgs = import nixpkgs {
          inherit system;
        };
        lib = pkgs.lib;
        nix = pkgs.nix;
        nix-vsbom = bombon.lib.${system}.buildBom nix {
          includeBuildtimeDependencies = true;
        };

        # TODO: do this using nix-instantiate like serge
        test-drv-json = pkgs.writeShellScriptBin "examine-derivation" ''
          cd ${nixpkgs.outPath}; ${pkgs.lix}/bin/nix derivation show --recursive -f . hello --arg config '{ contentAddressedByDefault = true; }'
        '';

        scope = pkgs.callPackage ./default.nix { nixpkgs = null; };
    in {
        packages = {
          inherit nix nix-vsbom test-drv-json;
          default = scope.laut;
        } // scope;


        checks = lib.filterAttrs (name: value:
          # since AND for trust models is not implemented yet
          # we only run one small and one large text
          # using builderA OR builderB as the trust model
          (name == "small") || (name == "large"))
          (import ./vm-tests {
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
            #sigstore
            pytest
            debugpy
            memory_profiler
          ] ++ [
            pkgs.pyright
          ] ++ [
            scope.lautr
          ]);
        in pkgs.mkShell {
          shellHook = ''
            export PATH=${lib.makeBinPath [ pkgs.diffoscope ]}:$PATH
          '';

          PYTEST_FOR_VSCODE = "${pythonEnv}/bin/pytest";
          buildInputs = [
            pkgs.cargo
            pkgs.rustc
            pythonEnv
            pkgs.souffle
            scope.lautr
          ];
        };
    });
}
