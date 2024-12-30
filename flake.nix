{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    bombon.url = "github:nikstur/bombon";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, bombon, flake-utils }@inputs:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
    let
        contentAddressedOverlay = final: prev: {
          config = prev.config // {
            contentAddressedByDefault = true;
          };
        };
        nixpkgs-ca = (import nixpkgs { inherit system; }).applyPatches {
          name = "nixpkgs-always-apply-ca";
          src = nixpkgs;
          patches = [ ./nixpkgs-ca/0001-always-enable-content-addresssing.patch ];
        };

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ contentAddressedOverlay ];
        };
        nix = pkgs.nix;
        nix-vsbom = bombon.lib.${system}.buildBom nix {
          includeBuildtimeDependencies = true;
        };

        trace-signatures = pkgs.python3.pkgs.buildPythonApplication {
          pname = "trace-signatures";
          version = "0.1.0";
          format = "pyproject";

          src = ./.;

          nativeBuildInputs = with pkgs.python3.pkgs; [
            setuptools
            setuptools-scm
          ];

          propagatedBuildInputs = with pkgs.python3.pkgs; [
            rfc8785
            pyjwt
            cryptography
            boto3
            click
            loguru
          ];

          pythonImportsCheck = [ "trace_signatures" ];
        };

    in {
        packages = {
          inherit nix nix-vsbom trace-signatures;
          default = trace-signatures;
        };

        checks = let
            system = "x86_64-linux";
            in import ./test.nix {
                inherit pkgs nix-vsbom inputs contentAddressedOverlay trace-signatures nixpkgs-ca;
            };

        devShell = let
          pythonEnv = pkgs.python3.withPackages (ps: with ps; [
            rfc8785
            pyjwt
            cryptography
            boto3
            click
            loguru
          ]);
        in pkgs.mkShell {
          buildInputs = [
            pythonEnv
          ];
        };
    });
}