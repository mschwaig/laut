{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    nixpkgs.url = "github:mschwaig/nixpkgs/fix-swig-option-for-souffle-before-rebase";
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
        };
        nix = pkgs.nix;
        nix-vsbom = bombon.lib.${system}.buildBom nix {
          includeBuildtimeDependencies = true;
        };

        test-drv-json = pkgs.writeShellScriptBin "examine-derivation" ''
          nix derivation show --recursive ${nixpkgs-ca}#hello
        '';

        trace-signatures = pkgs.python3.pkgs.buildPythonApplication {
          pname = "trace-signatures";
          version = "0.1.0";
          format = "pyproject";

          src = ./.;

          nativeBuildInputs = with pkgs.python3.pkgs; [
            setuptools
            setuptools-scm
          ];

          checkPhase = "pytest";
          pytestCheckHook = ''
            export PATH=${nix}/bin,$PATH
          '';

          nativeCheckInputs = with pkgs.python3.pkgs; [
            pytest
            pytest-cov
          #  nix
          ];

          propagatedBuildInputs = with pkgs.python3.pkgs; [
            rfc8785
            pyjwt
            cryptography
            boto3
            click
            loguru
          ] ++ (with pkgs; [
            souffle
            swig
          ]);

          pythonImportsCheck = [ "trace_signatures" ];
        };

    in {
        packages = {
          inherit nix nix-vsbom trace-signatures test-drv-json;
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
            pytest
            pytest-cov
            debugpy
            memory_profiler
          ] ++ [
          pkgs.pyright
          ]);
        in pkgs.mkShell {
          PYTHONPATH = "./src:${pythonEnv}/${pythonEnv.sitePackages}";
          PYTEST_FOR_VSCODE = "${pythonEnv}/bin/pytest";
          buildInputs = [
            pythonEnv
            pkgs.souffle
          ];
        };
    });
}
