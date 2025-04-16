{
  system ? "x86_64-linux",
  scope ? pkgsIA.callPackage ./default.nix { },
  laut ? scope.laut,
  nixpkgs ? builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/4633a7c72337ea8fd23a4f2ba3972865e3ec685d.tar.gz";
    sha256 = "sha256:0z9jlamk8krq097a375qqhyj7ljzb6nlqh652rl4s00p2mf60f6r";
  },
  nixpkgs-ca ? builtins.fetchTarball {
    url = "https://github.com/mschwaig/nixpkgs/archive/nixpkgs-ca.tar.gz";
  },
  lib ? pkgsIA.lib,
  pkgsIA ? import nixpkgs { inherit system; },
  pkgsCA ? import nixpkgs {
    config.contentAddressedByDefault = true;
    inherit system;
  },
  pkgsCA' ? import nixpkgs-ca {
    # config.contentAddressedByDefault = true;
    system = "x86_64-linux";
  },
  nixpkgs-swh ? builtins.fetchTarball {
    url = "https://github.com/nix-community/nixpkgs-swh/archive/552356958e70967398072e085e50fc675243e5c1.tar.gz";
    sha256 = "1sxgwknm1a2yhb5njk2xl8lkyy600bcrra64m352gmdmilwjbd4s";
  },
  ...
}:

# this code is inspired by
# https://www.haskellforall.com/2020/11/how-to-use-nixos-for-lightweight.html
# and
# https://github.com/Mic92/cntr/blob/2a1dc7b2de304b42fe342e2f7edd1a8f8d4ab6db/vm-test.nix
let
  cachePort = 9000;
  testLib =  import (nixpkgs + "/nixos/lib/testing-python.nix") { inherit system; };
  nixpkgs-swh-patched = pkgsIA.applyPatches {
    name = "patch-swh-find-tarballs";
    src = nixpkgs-swh;
    patches = [ ./patches/nixpkgs-swh/0001-make-find-tarballs.nix-return-drvs-and-be-pure.patch ];
  };  
  findTarballFods = import (nixpkgs-swh-patched + "/scripts/find-tarballs.nix" );
  pkgA = pkgsIA.cowsay;

  accessKey = "BKIKJAA5BMMU2RHO6IBB";
  secretKey = "V7f1CwQqAcwo80UEIJEjc5gVQUSSx5ohQ9GSrr12";
  cacheCredentials = {
    AWS_ACCESS_KEY_ID = accessKey;
    AWS_SECRET_ACCESS_KEY = secretKey;
  };
  storeUrl = "s3://binary-cache?endpoint=http://cache:${builtins.toString cachePort}&region=eu-west-1";
  trivialPackageCaStr = lib.concatStringsSep "." trivialPackageCa;
  #  trivialPackageCa = [ "hello" ];
  trivialPackageCa = [
    "stdenv"
    "__bootPackages"
    "stdenv"
    "__bootPackages"
    "stdenv"
    "__bootPackages"
    "stdenv"
    "__bootPackages"
    "stdenv"
    "__bootPackages"
    "stdenv"
    "__bootPackages"
    "stdenv"
    "__bootPackages"
    "binutils"
  ];

  prefetchedSources = map (drv: drv.out.outPath) (findTarballFods { pkgs = pkgsIA; expr = lib.getAttrFromPath trivialPackageCa pkgsCA; });

  cache =
    { ... }:
    {
      virtualisation.writableStore = true;
      virtualisation.additionalPaths = [ pkgA ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      environment.systemPackages = [ pkgsIA.minio-client ];
      nix.extraOptions = "experimental-features = nix-command";
      services.minio = {
        enable = true;
        region = "eu-west-1";
        listenAddress = "127.0.0.1:9002";
        rootCredentialsFile = pkgsIA.writeText "minio-credentials" ''
          MINIO_ROOT_USER=${accessKey}
          MINIO_ROOT_PASSWORD=${secretKey}
        '';
      };

      environment.variables = cacheCredentials;

      services.caddy = {
        enable = true;
        virtualHosts."http://cache:9000" = {
          extraConfig = ''
            reverse_proxy localhost:9002
          '';
        };
      };

      networking.firewall.allowedTCPPorts = [
        cachePort
        9001
      ];
    };

  makeBuilder =
    { privateKey, publicKey, ... }:
    {
      virtualisation.memorySize = 6144;
      virtualisation.cores = 4;
      virtualisation.writableStore = true;
      virtualisation.useNixStoreImage = true;
      systemd.services.nix-daemon.enable = true;
      virtualisation.mountHostNixStore = false;

      virtualisation.additionalPaths = [ pkgA ] ++ prefetchedSources;

      nix = {
        nixPath = [
          "nixpkgs=${nixpkgs}"
          "nixpkgs-ca=${
            pkgsIA.writeTextFile {
              name = "nixpkgs-ca";
              destination = "/default.nix";
              text =
              ''
                { ... }@args:
                let
                  pkgs = import <nixpkgs> (args // {
                    config = args.config or { } // {
                      contentAddressedByDefault = true;
                    };
                  });
                in pkgs
              '';
            }
          }"
        ];
        extraOptions =
          let
            emptyRegistry = builtins.toFile "empty-flake-registry.json" ''{"flakes":[],"version":2}''; # TODO: check if I should remove this
          in
          ''
            experimental-features = nix-command flakes ca-derivations
            flake-registry = ${emptyRegistry}
          '';
        settings = {
          trusted-substituters = [ ];
          post-build-hook = pkgsIA.writeShellScript "copy-to-cache" ''
            set -eux
            set -f # disable globbing

            # Create a sanitized filename from the derivation path
            SAFE_DRV_NAME=$(basename "$DRV_PATH" | tr -dc '[:alnum:].-')
            LOG_FILE="$HOME/hooklog-$SAFE_DRV_NAME"

            # Redirect all output to both the console and the derivation-specific log file
            exec > >(tee -a "$LOG_FILE") 2>&1

            [ -n "$OUT_PATHS" ]
            [ -n "$DRV_PATH" ]

            echo Pushing "$OUT_PATHS" to ${storeUrl}
            printf "%s" "$OUT_PATHS" | xargs nix copy --to "${storeUrl}" --no-require-sigs
            printf "%s" "$DRV_PATH"^'*' | xargs nix copy --to "${storeUrl}" --secret-key-files /etc/nix/private-key

            laut --debug sign-and-upload "$DRV_PATH" --secret-key-file /etc/nix/private-key --to "${storeUrl}"
          '';
        };
      };

      system.activationScripts.postGeneration = {
        text = ''
          echo "Running post-generation script"
          STORE_DIR="mktemp -d"
        '';
        deps = [ ]; # Add dependencies if needed
      };

      environment = {
        variables = cacheCredentials;
        etc = {
          "nix/private-key".source = privateKey;
          "nix/public-key".source = publicKey;
        };
        systemPackages = with pkgsIA; [
          nix
          git
          laut
        ];
      };
    };

  makeTest =
    name:
    {
      extraConfig,
      trustModel ? null,
    }:
    testLib.runTest {
      name = "sbom-verify-${name}";

      nodes = {
        inherit cache;

        builderA = makeBuilder {
          privateKey = ./testkeys/builderA_key.private;
          publicKey = ./testkeys/builderA_key.public;
        };
        builderB = makeBuilder {
          privateKey = ./testkeys/builderB_key.private;
          publicKey = ./testkeys/builderB_key.public;
        };
        # TODO: add nixpkgs-mirror;

        ${name} =
          { ... }:
          {
            virtualisation.memorySize = 2048;
            virtualisation.cores = 2;
            virtualisation.writableStore = true;
            virtualisation.useNixStoreImage = true;
            systemd.services.nix-daemon.enable = true;
            virtualisation.mountHostNixStore = false;

            nix = {
              nixPath = [
                "nixpkgs=${nixpkgs}"
                "nixpkgs-ca=${
                  pkgsIA.writeTextFile {
                    name = "nixpkgs-ca";
                    destination = "/default.nix";
                    text =
                    ''
                      { ... }@args:
                      let
                        pkgs = import <nixpkgs> (args // {
                          config = args.config or { } // {
                            contentAddressedByDefault = true;
                          };
                        });
                      in pkgs
                    '';
                  }
                }"
              ];
              extraOptions =
              let
                emptyRegistry = builtins.toFile "empty-flake-registry.json" ''{"flakes":[],"version":2}''; # TODO: check if I should remove this
              in
              ''
                experimental-features = nix-command flakes ca-derivations
                flake-registry = ${emptyRegistry}
              '';
            };

            environment.systemPackages = with pkgsIA; [
              nix
              git
              laut
            ];
          }
          // extraConfig;
      };

      # Test script to verify the setup
      testScript = ''
        from concurrent.futures import ThreadPoolExecutor
        from typing import Callable
        from functools import wraps

        executor = ThreadPoolExecutor(max_workers=5)

        def run_in_background(func: Callable):
          @wraps(func)
          def wrapper(*args, **kwargs):
            return executor.submit(func, *args, **kwargs)

          return wrapper

        cache.start()
        cache.forward_port(9000, 9000)
        cache.forward_port(9001, 9001)
        cache.wait_for_unit("minio")
        cache.wait_for_open_port(9002)
        cache.wait_for_open_port(${builtins.toString cachePort})

        # configure cache
        cache.succeed("mc config host add minio http://cache:${builtins.toString cachePort} ${accessKey} ${secretKey} --api s3v4")
        cache.succeed("mc mb minio/binary-cache")
        cache.succeed("mc anonymous set download minio/binary-cache") # allow public read

        @run_in_background
        def boot_and_configure(builder):
          builder.start()
          builder.wait_for_unit("network.target")

          builder.succeed("curl -fv http://cache:${builtins.toString cachePort}/minio/health/ready")

          builder.wait_for_unit("default.target")

        #future1, future2 = boot_and_configure(builderA), boot_and_configure(builderB)
        future1 = boot_and_configure(builderA)

        future1.result()
        #future2.result()

        @run_in_background
        def build_and_upload(builder):
          # builder.succeed("nix build --expr 'derivation { name = \"test\"; builder = \"/bin/sh\"; args = [ \"-c\" \"echo $RANDOM > $out\" ]; system = \"x86_64-linux\"; __contentAddressed = true; }' --secret-key-files \"/etc/nix/private-key\" --no-link --print-out-paths")
          builder.succeed("nix build -f '<nixpkgs-ca>' ${trivialPackageCaStr} --secret-key-files \"/etc/nix/private-key\" -L")

        #future1, future2  =  build_and_upload(builderA), build_and_upload(builderB)
        future1 = build_and_upload(builderA)

        future1.result()
        #future2.result()

        builderA.shutdown()
        #builderB.shutdown()

        # for now we only care about extracting the cache outputs from this test
        # and using them as input for the unit and integration tests in python
        ${name}.start()
        ${name}.wait_for_unit("network.target")

        ${name}.succeed("laut verify --cache \"${storeUrl}\" --trusted-key ${./testkeys/builderA_key.public} $(nix-instantiate '<nixpkgs-ca>' -A ${trivialPackageCaStr})")

        # ${name}.fail("nix path-info ${pkgA}")
        # ${name}.succeed("nix store info --store '${storeUrl}' >&2")
        # ${name}.succeed("nix copy --no-check-sigs --from '${storeUrl}' ${pkgA}")
        # ${name}.succeed("nix path-info ${pkgA}")

        # ${name}.succeed("nix-store --verify")

        # TODO: run test script
        # using specific trust model

        # run verification tool
        # run nix build
      '';
    };
in
{
  # Full local reproducibility model - trusts only itself
  fullReproVM = makeTest "full_local_repro" {
    extraConfig = { };
    # extraConfig.nix = {
    #   extraOptions = "experimental-features = nix-command flakes";
    #   settings = {
    #       substituters = [ ];
    #       trusted-public-keys = [ ];
    #   };
    # };
    #  trust_model = Builder(self())
  };

  # Trusted infrastructure model - trusts central cache
  trustedInfraVM = makeTest "trusted_infra" {
    extraConfig.nix = {
      extraOptions = "experimental-features = nix-command flakes";
      settings = {
        substituters = [ "http://cache.local" ];
        trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
      };
    };
    #  trust_model = threshold(1,
    #   Builder(self()),
    #   Signer("cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=", legacy=true))
  };

  # Distributed trust model - requires multiple builder agreement
  distributedTrustVM = makeTest "distributed_trust" {
    extraConfig.nix = {
      extraOptions = "experimental-features = nix-command flakes";
      settings = {
        substituters = [
          "http://builder1.local"
          "http://builder2.local"
        ];
        trusted-public-keys = [
          "builder1.local:${placeholder "BUILDER1_KEY"}"
          "builder2.local:${placeholder "BUILDER2_KEY"}"
        ];
      };
    };
    #  trust_model = threshold(2,
    #   Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU="),
    #   Builder("builderB:iN9OEB6nRfDK0Ae8fscfOZAjWPXn4CdIIHiaMwWxXQk="))
  };
  attestBuilder = makeTest "attest_builder" {
    extraConfig.nix.settings = {
      extraConfig.nix = {
        extraOptions = "experimental-features = nix-command flakes";
        substituters = [ "http://cache.local" ];
        trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
      };
    };
    #  trust_model = Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU=",
    #     sw_flake = "github:nixos/nixpkgs-builders/8d99dd5e331e9fc8f3480d739b709eafc1e4ceb6#amd-tpm-2.0",
    #     host_sw_criteria = SW_CRITERIA.TPM-2.0_STRICT,
    #     host_hw_criteria = HW_CRTIERIA.HP_MILAN_NO_PUBLIC_VULN,
    #     host_identity = "smRvhWX9+vVTe3gpNsAp4EuJmUtdw2Ih9xcp+Mjd+6g=",
    #     host_sw_exclude = SW_CRITERIA.DRVS_WITH_VULNS + nixpkgsRange("xyutils", "5.6.0", "5.6.1"))
  };

  # used this to figure out what was wrong with earlier versions of my
  # content addressed nixpkgs instance
  weirdDrv.ca' = lib.getAttrFromPath trivialPackageCa pkgsCA';
  weirdDrv.ca = lib.getAttrFromPath trivialPackageCa pkgsCA;
  weirdDrv.ia = lib.getAttrFromPath trivialPackageCa pkgsIA;

  weirdDrv.mk-diff = pkgsIA.writeShellScriptBin "mk-diff" ''
    ${lib.getExe' pkgsIA.nix "nix-instantiate"} -A weirdDrv."ca" test.nix | xargs ${lib.getExe pkgsIA.nix} derivation show | ${lib.getExe pkgsIA.jq} > ca.json
    ${lib.getExe' pkgsIA.nix "nix-instantiate"} -A weirdDrv."ia" test.nix | xargs ${lib.getExe pkgsIA.nix} derivation show | ${lib.getExe pkgsIA.jq} > ia.json
    ${lib.getExe pkgsIA.delta} ia.json ca.json
  '';
}
