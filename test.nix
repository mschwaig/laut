{ pkgs, nix-vsbom, inputs, contentAddressedOverlay, ... }:

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
  storeUrl = "s3://binary-cache?endpoint=http://cache:${builtins.toString cachePort}&region=eu-west-1";

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

      environment.variables = {
        AWS_ACCESS_KEY_ID = accessKey;
        AWS_SECRET_ACCESS_KEY = secretKey;
      };

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

      nixpkgs.overlays = [ contentAddressedOverlay ];
      nix = {
        registry.nixpkgs.flake = inputs.nixpkgs;
        extraOptions = ''
        experimental-features = nix-command flakes ca-derivations
        '';
        settings = {
          trusted-substituters = [ ];
          post-build-hook = pkgs.writeShellScript "copy-to-cache" ''
            set -eux
            set -f # disable globbing
            #exec > >(tee -a $HOME/hooklog) 2>&1

            export AWS_ACCESS_KEY_ID=${accessKey}
            export AWS_SECRET_ACCESS_KEY=${secretKey}

            [ -n "$OUT_PATHS" ]
            [ -n "$DRV_PATH" ]

            echo Pushing "$OUT_PATHS" to ${storeUrl}
            printf "%s" "$OUT_PATHS" | xargs nix copy --to "${storeUrl}" --no-require-sigs
            printf "%s" "$DRV_PATH"^'*' | xargs nix copy --to "${storeUrl}" --no-require-sigs
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
        variables = {
          AWS_ACCESS_KEY_ID = accessKey;
          AWS_SECRET_ACCESS_KEY = secretKey;
        };
        etc = {
          "nix/private-key".source = privateKey;
          "nix/public-key".source = publicKey;
        };
        systemPackages = with pkgs; [
          nix
          git
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

          nix.registry.nixpkgs.flake = inputs.nixpkgs;
          nixpkgs.overlays = [ contentAddressedOverlay ];

          environment.systemPackages = with pkgs; [
            nix
            git
          ];
      } // extraConfig;
    };

    # Test script to verify the setup
    testScript = ''
    cache.start()
    cache.forward_port(9001, 9001)
    cache.wait_for_unit("minio")
    cache.wait_for_open_port(9002)
    cache.wait_for_open_port(${builtins.toString cachePort})

    # configure cache
    cache.succeed("mc config host add minio http://cache:${builtins.toString cachePort} ${accessKey} ${secretKey} --api s3v4")
    cache.succeed("mc mb minio/binary-cache")
    cache.succeed("mc policy set download minio/binary-cache") # allow public read

    builderA.start()
    #builderB.start()
    builderA.wait_for_unit("network.target")
    #builderB.wait_for_unit("network.target")

    builderA.succeed("curl -fv http://cache:${builtins.toString cachePort}/minio/health/ready")

    builderA.succeed("mkdir -p ~/.config/nixpkgs")
    builderA.succeed("echo \"{ contentAddressedByDefault = true; }\" > ~/.config/nixpkgs/config.nix")

    builderA.wait_for_unit("default.target")
    builderA.succeed("nix build --impure nixpkgs#hello")

    # builderA.shutdown()
    # builderB.shutdown()
    
    # ${name}.start()
    # ${name}.wait_for_unit("network.target")
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
    extraConfig.nix = {
      extraOptions = "experimental-features = nix-command flakes";
      settings = {
          substituters = [ ];
          trusted-public-keys = [ ];
      };
    };
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
