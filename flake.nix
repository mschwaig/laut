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

        nix-verify-souffle = pkgs.python3.pkgs.buildPythonApplication {
          pname = "nix_verify_souffle";
          version = "0.1.0";

          src = ./datalog;

          format = "other";
          build-system = [
            pkgs.python3.pkgs.hatchling
          ];
          nativeBuildInputs = with pkgs; [
            souffle
          ];

          pythonImportsCheck = [ "nix_verify_souffle" ];
          doCheck = true;

          buildPhase = ''
            souffle -o nix_verify_souffle $src/nix_verify.dl
            souffle -s python $src/nix_verify.dl
          '';

          installPhase = ''
            PKGS_PATH=$out/${pkgs.python3.sitePackages}/nix_verify_souffle
            mkdir -p $out/bin $PKGS_PATH
            cp nix_verify_souffle $out/bin/
            touch $PKGS_PATH/__init__.py
            cp SwigInterface.py $PKGS_PATH/SwigInterface.py
            cp _SwigInterface.so $PKGS_PATH/_SwigInterface.so
          '';
        };

        laut-f = sign-only: pkgs.python3.pkgs.buildPythonApplication {
          pname = "laut";
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

          # disable this for now
          # it is no clear to me if running these tests in the sandbox would make sense
          # because they have to inspect and reason about store contents
          # excpt if we mock all of that away
          doCheck = false;

          nativeCheckInputs = with pkgs.python3.pkgs; [
            pytest
            pytest-cov
          ];

          propagatedBuildInputs = with pkgs.python3.pkgs; [
            rfc8785
            pyjwt
            cryptography
            boto3
            click
            sigstore
            loguru
          ] ++ (if sign-only then [] else [
            nix-verify-souffle
          ]);

          pythonImportsCheck = [ "laut" ];
        };

        laut = laut-f false;
        laut-sign-only = laut-f true;

    in {
        packages = {
          inherit nix nix-vsbom laut laut-sign-only nix-verify-souffle test-drv-json;
          default = laut;
        };

        checks = lib.filterAttrs (name: value:
          # since trust models are not implemented yet
          # it makes no sense to run more than one VM test
          (name == "fullReproVM"))
          (import ./test.nix {
            inherit pkgs nix-vsbom inputs laut nixpkgs-ca;
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
            pytest-cov
            debugpy
            memory_profiler
          ] ++ [
            pkgs.pyright
          ] ++ [
            nix-verify-souffle
          ]);
        in pkgs.mkShell {
          PYTHONPATH = "./src:${pythonEnv}/${pythonEnv.sitePackages}";
          PYTEST_FOR_VSCODE = "${pythonEnv}/bin/pytest";
          buildInputs = [
            pythonEnv
            pkgs.souffle
            nix-verify-souffle
          ];
        };
    });
}
