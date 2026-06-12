{
  description = "Verifiable SBOM VM Tests";

  inputs = {
    # `nixpkgs` is the infra Nix evaluator: it builds laut, qemu, and the
    # writers/wrappers the VM tests need. Rolling on purpose — the infra
    # doesn't need to be pinned and we want it tracking upstream.
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    # `nixpkgs-under-test` is the package set whose builds we sign and verify.
    # Pinned so the same drv hashes show up across runs and across the
    # IA/CA modes (which derive both from this same input).
    nixpkgs-under-test.url = "github:nixos/nixpkgs/979daf34c8cacebcd917d540070b52a3c2b9b16e";
    bombon.url = "github:nikstur/bombon";
  };

  outputs = { self, nixpkgs, nixpkgs-under-test, bombon }@inputs:
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
        # Change to the drv_lookup directory first
        cd tests/data/drv_lookup

        # Generate JSON data and pipe directly to the Python script
        (cd ${nixpkgs.outPath} && ${pkgs.lix}/bin/nix derivation show --recursive -f . hello --arg config '{ contentAddressedByDefault = true; }') | \
        ${pkgs.python3}/bin/python3 ${./tests/data/drv_lookup/generate_test_data_with_aterm.py} \
          hello-ca-recursive-unresolved.drv \
          hello-ca-recursive-unresolved-aterm.json
      '';

      scope = pkgs.callPackage ./default.nix { nixpkgs = null; };
    in {
      packages.${system} = {
        inherit nix nix-vsbom test-drv-json;
        inherit (scope) laut laut-sign-only;
        default = scope.laut;
      };


      checks.${system} = (import ./vm-tests {
          inherit pkgs nixpkgs-under-test;
          inherit (scope) laut;
        });

      devShell.${system} = pkgs.mkShell {
        shellHook = ''
          export PATH=${lib.makeBinPath [ pkgs.difftastic ]}:$PATH
        '';

        buildInputs = [
          pkgs.cargo
          pkgs.rustc
        ];

        nativeBuildInputs = [
          pkgs.protobuf
        ];
      };
  };
}
