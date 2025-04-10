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
        pkgs = import nixpkgs {
          inherit system;
        };
        lib = pkgs.lib;
        nix = pkgs.nix;
        nix-vsbom = bombon.lib.${system}.buildBom nix {
          includeBuildtimeDependencies = true;
        };

        test-drv-json = pkgs.writeShellScriptBin "examine-derivation" ''
          cd ${nixpkgs.outPath}; ${pkgs.lix}/bin/nix derivation show --recursive -f . hello --arg config '{ contentAddressedByDefault = true; }'
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

          src = lib.sourceByRegex ./. [
            "^src(/laut(/.*)?)?$"
            "^tests(/.*)?$"
            "^testkeys(/.*)?$"
            "^pyproject\.toml$"
            "^LICENSE\.md$"
            "^README\.md$"
          ];

          nativeBuildInputs = with pkgs.python3.pkgs; [
            setuptools
            setuptools-scm
          ] ++ (if sign-only then [] else [
            pytestCheckHook
          ]);

          postPatch =  if sign-only then ''
            substituteInPlace "src/laut/build_config.py" \
              --replace-fail "sign_only = False" "sign_only = True"
          '' else "";

          nativeCheckInputs = with pkgs.python3.pkgs; [
            pytest
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

          preCheck = if sign-only then "" else ''
            export PATH=${lib.makeBinPath [ pkgs.diffoscope ]}:$PATH
          '';

          postInstall = if sign-only then "" else ''
            wrapProgram $out/bin/laut \
              --prefix PATH : ${lib.makeBinPath [ pkgs.diffoscope ]}
          '';

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
            inherit pkgs nix-vsbom inputs laut system;
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
          shellHook = ''
            export PATH=${lib.makeBinPath [ pkgs.diffoscope ]}:$PATH
          '';

          PYTEST_FOR_VSCODE = "${pythonEnv}/bin/pytest";
          buildInputs = [
            pythonEnv
            pkgs.souffle
            nix-verify-souffle
          ];
        };
    });
}
