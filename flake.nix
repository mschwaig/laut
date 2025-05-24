{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    bombon.url = "github:nikstur/bombon";
  };

  outputs = { self, nixpkgs, bombon }@inputs:
    let
      system = "x86_64-linux";
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
      packages.${system} = {
        inherit nix nix-vsbom test-drv-json;
        inherit (scope) laut laut-sign-only lautr;
        default = scope.laut;
      };


      checks.${system} = (import ./vm-tests {
          pkgsIA = pkgs;
          inherit nixpkgs;
          inherit (scope) laut;
        });

      devShell.${system} = let
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
          export PYTHONPATH="$PWD/src:$PYTHONPATH"
        '';

        PYTEST_FOR_VSCODE = "${pythonEnv}/bin/pytest";
        buildInputs = [
          pkgs.cargo
          pkgs.rustc
          pythonEnv
        ];

        nativeBuildInputs = [
          pkgs.protobuf
        ];
      };
  };
}
