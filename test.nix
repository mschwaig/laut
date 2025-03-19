{ pkgs, nix-vsbom, laut, inputs, nixpkgs-ca, ... }:

# this code is inspired by
# https://www.haskellforall.com/2020/11/how-to-use-nixos-for-lightweight.html
# and
# https://github.com/Mic92/cntr/blob/2a1dc7b2de304b42fe342e2f7edd1a8f8d4ab6db/vm-test.nix
let
 # ia-pkgs = pkgs;
 # pkgs = ca-pkgs;
  cachePort = 9000;

  pkgA = pkgs.cowsay;

  accessKey = "BKIKJAA5BMMU2RHO6IBB";
  secretKey = "V7f1CwQqAcwo80UEIJEjc5gVQUSSx5ohQ9GSrr12";
  cacheCredentials = {
    AWS_ACCESS_KEY_ID = accessKey;
    AWS_SECRET_ACCESS_KEY = secretKey;
  };
  storeUrl = "s3://binary-cache?endpoint=http://cache:${builtins.toString cachePort}&region=eu-west-1";
  trivialPackageCa = "nixpkgs-ca#stdenv.__bootPackages.stdenv.__bootPackages.stdenv.__bootPackages.stdenv.__bootPackages.stdenv.__bootPackages.stdenv.__bootPackages.stdenv.__bootPackages.binutils";

  cache = { ... }: {
      virtualisation.writableStore = true;
      virtualisation.additionalPaths = [ pkgA ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      environment.systemPackages = [ pkgs.minio-client ];
      nix.extraOptions = "experimental-features = nix-command";
      services.minio = {
        enable = true;
        region = "eu-west-1";
        listenAddress = "127.0.0.1:9002";
        rootCredentialsFile = pkgs.writeText "minio-credentials" ''
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

      networking.firewall.allowedTCPPorts = [ cachePort 9001 ];
  };
  makeBuilder  = { privateKey, publicKey, ... }: {
      virtualisation.memorySize = 16384;
      virtualisation.cores = 8;
      virtualisation.diskSize = 4096;
      virtualisation.writableStore = true;
      virtualisation.useNixStoreImage = true;
      systemd.services.nix-daemon.enable = true;
      virtualisation.mountHostNixStore = false;

      virtualisation.additionalPaths = [ pkgA ];

      nix = {
        registry = {
          nixpkgs-ca.flake = nixpkgs-ca;
          nixpkgs.flake = inputs.nixpkgs;
        };
        extraOptions =
        let
          emptyRegistry = builtins.toFile "empty-flake-registry.json" ''{"flakes":[],"version":2}'';
        in ''
          experimental-features = nix-command flakes ca-derivations
          flake-registry = ${emptyRegistry}
        '';
        settings = {
          trusted-substituters = [ ];
          post-build-hook = pkgs.writeShellScript "copy-to-cache" ''
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

            laut sign "$DRV_PATH" --secret-key-file /etc/nix/private-key --to "${storeUrl}"
          '';
        };
      };

      system.activationScripts.postGeneration = {
        text = ''
          echo "Running post-generation script"
          STORE_DIR="mktemp -d"
          nix --store $STORE_DIR build nixpkgs#hello
        '';
        deps = [];  # Add dependencies if needed
      };

      environment = {
        variables = cacheCredentials;
        etc = {
          "nix/private-key".source = privateKey;
          "nix/public-key".source = publicKey;
        };
        systemPackages = with pkgs; [
          nix
          git
          laut
        ];
      };
  };

  makeTest = name: { extraConfig, trustModel ? null }: pkgs.nixosTest {
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

      ${name} = { ... }: {
          virtualisation.memorySize = 2048;
          virtualisation.cores = 2;
          virtualisation.diskSize = 4096;
          virtualisation.writableStore = true;
          virtualisation.useNixStoreImage = true;
          systemd.services.nix-daemon.enable = true;
          virtualisation.mountHostNixStore = false;

          nix.registry = {
            nixpkgs-ca.flake = nixpkgs-ca;
            nixpkgs.flake = inputs.nixpkgs;
          };
          nix.extraOptions =
          let
            emptyRegistry = builtins.toFile "empty-flake-registry.json" ''{"flakes":[],"version":2}'';
          in ''
            experimental-features = nix-command flakes ca-derivations
            flake-registry = ${emptyRegistry}
          '';

          environment.systemPackages = with pkgs; [
            nix
            git
            laut
          ];
      } // extraConfig;
    };

    # Test script to verify the setup
    testScript = ''
    from threading import Thread
    from typing import Callable
    from functools import wraps

    def run_in_background(func: Callable):
      @wraps(func)
      def wrapper(*args, **kwargs):
        thread = Thread(target=func, args=args, kwargs=kwargs, daemon=True)
        thread.start()
        return thread
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

    t1, t2 = boot_and_configure(builderA), boot_and_configure(builderB)

    t1.join()
    t2.join()

    @run_in_background
    def build_and_upload(builder):
      builder.succeed("nix build --expr 'derivation { name = \"test\"; builder = \"/bin/sh\"; args = [ \"-c\" \"echo $RANDOM > $out\" ]; system = \"x86_64-linux\"; __contentAddressed = true; }' --secret-key-files \"/etc/nix/private-key\" --no-link --print-out-paths")
      builder.succeed("nix build ${trivialPackageCa} --secret-key-files \"/etc/nix/private-key\"")

    t1, t2 =  build_and_upload(builderA), build_and_upload(builderB)

    t1.join()
    t2.join()

    #builderA.shutdown()
    #builderB.shutdown()

    ${name}.start()
    ${name}.wait_for_unit("network.target")

    ${name}.succeed("mkdir -p ~/.config/nixpkgs")
    ${name}.succeed("laut verify --cache \"${storeUrl}\" --trusted-key ${./testkeys/builderA_key.public} --trusted-key ${./testkeys/builderB_key.public} ${trivialPackageCa}")

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
in {
  # Full local reproducibility model - trusts only itself
  fullReproVM = makeTest "full_local_repro" {
    extraConfig = {};
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

}
