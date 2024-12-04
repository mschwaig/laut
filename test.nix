{ pkgs, makeTest, nix-vsbom, ... }:

# this code is inspired by
# https://www.haskellforall.com/2020/11/how-to-use-nixos-for-lightweight.html
# and
# https://github.com/Mic92/cntr/blob/2a1dc7b2de304b42fe342e2f7edd1a8f8d4ab6db/vm-test.nix
let
  cachePort = 5000;
  cache = { config, pkgs, ... }: {
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      services.nix-serve = {
        enable = true;
        # consider using ng package
        # secretKeyFile = pkgs.writeText "secret-key" "secret-key-content";
      };

      networking.firewall.allowedTCPPorts = [ cachePort ];
  };
  makeBuilder  = { pkgs, ... }: {
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

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
  makeTest = name: { extraConfig, trustModel ? null }: pkgs.nixosTest {
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
    cache.wait_for_unit("nix-serve")
    cache.wait_for_open_port(${builtins.toString cachePort})

    builderA.start()
    builderB.start()
    builderA.wait_for_unit("network.target")
    builderB.wait_for_unit("network.target")
    builderA.shutdown()
    builderB.shutdown()
    
    ${name}.start()
    ${name}.wait_for_unit("network.target")
    ${name}.succeed("curl http://cache:5000/nix-cache-info")

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
