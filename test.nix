{ pkgs, ca-pkgs, nix-vsbom, ... }:

# this code is inspired by
# https://www.haskellforall.com/2020/11/how-to-use-nixos-for-lightweight.html
# and
# https://github.com/Mic92/cntr/blob/2a1dc7b2de304b42fe342e2f7edd1a8f8d4ab6db/vm-test.nix
let
  ia-pkgs = pkgs;
  pkgs = ca-pkgs;
  cachePort = 9000;

  pkgA = pkgs.cowsay;

  accessKey = "BKIKJAA5BMMU2RHO6IBB";
  secretKey = "V7f1CwQqAcwo80UEIJEjc5gVQUSSx5ohQ9GSrr12";
  env = "AWS_ACCESS_KEY_ID=${accessKey} AWS_SECRET_ACCESS_KEY=${secretKey}";
  storeUrl = "s3://binary-cache?endpoint=http://cache:9000&region=eu-west-1";

  cache = { config, pkgs, ... }: {
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      environment.systemPackages = [ pkgs.minio-client ];
      services.minio = {
        enable = true;
        region = "eu-west-1";
        rootCredentialsFile = pkgs.writeText "minio-credentials" ''
          MINIO_ROOT_USER=${accessKey}
          MINIO_ROOT_PASSWORD=${secretKey}
        '';
      };

      networking.firewall.allowedTCPPorts = [ cachePort ];
  };
  makeBuilder  = { pkgs, ... }: {
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      virtualisation.additionalPaths = [ pkgA ];

      nix = {
        settings = {
          experimental-features = [ "nix-command" "flakes" ];
          trusted-substituters = [ ];
          post-build-hook = pkgs.writeShellScript "copy-to-cache" ''
            echo "Running post-build hook"
            echo $1 $2
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

      environment.systemPackages = with pkgs; [
        nix
        git
      ];
  };
  makeTest = name: { extraConfig, trustModel ? null }: ia-pkgs.nixosTest {
    name = "sbom-verify-${name}";

    nodes = {
      inherit cache;

      builderA = makeBuilder { inherit pkgs; };
      builderB = makeBuilder { inherit pkgs; };
      # TODO: add builder-A builder-B nixpkgs-mirror;

      ${name} = { config, pkgs, ... }: {
          virtualisation.memorySize = 2048;
          virtualisation.cores = 2;

          environment.systemPackages = with pkgs; [
            nix
            git
          ];
      } // extraConfig;
    };

    # Test script to verify the setup
    testScript = ''
    cache.start()
    cache.wait_for_unit("minio")
    cache.wait_for_open_port(${builtins.toString cachePort})

    # configure cache
    server.succeed("mc config host add minio http://localhost:9000 ${accessKey} ${secretKey} --api s3v4")
    server.succeed("mc mb minio/binary-cache")
    server.succeed("mc policy set download local/binary-cache") # allow public read

    builderA.start()
    builderA.succeed("${env} nix copy --to '${storeUrl}' ${pkgA}")
    builderB.start()
    builderA.wait_for_unit("network.target")
    builderB.wait_for_unit("network.target")

    builderA.succeed("curl -f http://cache:${builtins.toString cachePort}/minio/health/ready")
    builderA.succeed("""
      nix-store --generate-binary-cache-key cache /etc/nix/key.private /etc/nix/key.public
      nix copy --to 's3://cache?endpoint=http://cache:9000&region=eu-west-1:${builtins.toString cachePort}&scheme=http' /nix/store/*-bash-*
    """)

    builderA.shutdown()
    builderB.shutdown()
    
    ${name}.start()
    ${name}.wait_for_unit("network.target")
    ${name}.fail("nix path-info ${pkgA}")
    ${name}.succeed("${env} nix store info --store '${storeUrl}' >&2")
    ${name}.succeed("${env} nix copy --no-check-sigs --from '${storeUrl}' ${pkgA}")
    ${name}.succeed("nix path-info ${pkgA}")
    ${name}.succeed("curl http://cache:9000/nix-cache-info")

    ${name}.succeed("nix-store --verify")
    ${name}.succeed("nix-store --realise /nix/store/*-bash-*")

    # TODO: run test script
    # using specific trust model

    # run verification tool
    # run nix build
    '';
  };
in {
  # Full local reproducibility model - trusts only itself
  fullReproVM = makeTest "full_local_repro" {
    extraConfig.nix.settings = {
        substituters = [ ];
        trusted-public-keys = [ ];
    };
    #  trust_model = Builder(self())
  };

  # Trusted infrastructure model - trusts central cache
  trustedInfraVM = makeTest "trusted_infra" {
    extraConfig.nix.settings = {
        substituters = [ "http://cache.local" ];
        trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
    };
    #  trust_model = threshold(1,
    #   Builder(self()),
    #   Signer("cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=", legacy=true))
  };

  # Distributed trust model - requires multiple builder agreement
  distributedTrustVM = makeTest "distributed_trust" {
    extraConfig.nix.settings = {
      substituters = [
        "http://builder1.local"
        "http://builder2.local"
      ];
      trusted-public-keys = [
        "builder1.local:${placeholder "BUILDER1_KEY"}"
        "builder2.local:${placeholder "BUILDER2_KEY"}"
      ];
    };
    #  trust_model = threshold(2,
    #   Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU="),
    #   Builder("builderB:iN9OEB6nRfDK0Ae8fscfOZAjWPXn4CdIIHiaMwWxXQk="))
  };
  attestBuilder = makeTest "attest_builder" {
    extraConfig.nix.settings = {
        substituters = [ "http://cache.local" ];
        trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
    };
    #  trust_model = Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU=",
    #     sw_flake = "github:nixos/nixpkgs-builders/8d99dd5e331e9fc8f3480d739b709eafc1e4ceb6#amd-tpm-2.0",
    #     host_sw_criteria = SW_CRITERIA.TPM-2.0_STRICT,
    #     host_hw_criteria = HW_CRTIERIA.HP_MILAN_NO_PUBLIC_VULN,
    #     host_identity = "smRvhWX9+vVTe3gpNsAp4EuJmUtdw2Ih9xcp+Mjd+6g=",
    #     host_sw_exclude = SW_CRITERIA.DRVS_WITH_VULNS + nixpkgsRange("xyutils", "5.6.0", "5.6.1"))
  };

}
