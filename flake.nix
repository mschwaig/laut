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
          format = "other";

          src = ./.;

          nativeBuildInputs = with pkgs.python3.pkgs; [
            wrapPython
          ];

          propagatedBuildInputs = with pkgs.python3.pkgs; [
            rfc8785
            pyjwt
            cryptography
            boto3
            click
          ];

          dontUnpack = true;

          installPhase = ''
            mkdir -p $out/bin $out/lib

            # Copy the script to lib directory
            cp $src/trace-signatures.py $out/lib/

            # Create the wrapper script that will be placed in bin/
            cat > $out/bin/trace-signatures.py << EOF
            #!${pkgs.python3}/bin/python3
            import sys
            import os

            script_dir = os.path.dirname(os.path.realpath(__file__))
            script_path = os.path.join(os.path.dirname(script_dir), "lib", "trace-signatures.py")

            if __name__ == '__main__':
                with open(script_path) as f:
                    exec(f.read())
            EOF

            # Make both files executable
            chmod +x $out/lib/trace-signatures.py
            chmod +x $out/bin/trace-signatures.py

            # Create a symlink without .py extension
            ln -s trace-signatures.py $out/bin/trace-signatures

            # Wrap both the .py and non-.py versions
            wrapPythonProgramsIn "$out/bin" "$out $propagatedBuildInputs"
          '';
        };

    in {
        packages = {
          inherit nix nix-vsbom trace-signatures;
          default = trace-signatures;
        };

        checks = let
            system = "x86_64-linux";
            in import ./test.nix {
                inherit pkgs nix-vsbom inputs contentAddressedOverlay trace-signatures;
            };

        devShell = let
          pythonEnv = pkgs.python3.withPackages (ps: with ps; [
            rfc8785 
            pyjwt 
            cryptography
            boto3
            click
          ]);
        in pkgs.mkShell {
          buildInputs = [
            pythonEnv
          ];
        };
    });
}