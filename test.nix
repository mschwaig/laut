{ pkgs, makeTest, nix-vsbom, ... }:

# this code is inspired by
# https://www.haskellforall.com/2020/11/how-to-use-nixos-for-lightweight.html
# and
# https://github.com/Mic92/cntr/blob/2a1dc7b2de304b42fe342e2f7edd1a8f8d4ab6db/vm-test.nix
let
  cache = { config, pkgs, ... }: {
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      
      services.nginx = {
      enable = true;
      virtualHosts."cache.local" = {
          locations."/" = {
          root = "/var/cache";
          extraConfig = ''
              autoindex on;
          '';
          };
      };
      };
      
      networking.firewall.allowedTCPPorts = [ 80 ];
      networking.extraHosts = ''
      127.0.0.1 cache.local
      '';
      
      # Create directory for cache data
      system.activationScripts.createCache = ''
      mkdir -p /var/cache
      chmod 755 /var/cache
      '';
  };
  makeBuilder = "";
  makeTest = name: { extraConfig, trustModel ? null }: pkgs.nixosTest {
    name = "sbom-verify-${name}";
    
    nodes = {
      inherit cache;
      # TODO: add builder-A builder-B nixpkgs-mirror;

      ${name} = { config, pkgs, ... }: {
          virtualisation.memorySize = 2048;
          virtualisation.cores = 2;
          
          networking.extraHosts = ''
          192.168.1.1 cache.local
          '';
          
          environment.systemPackages = with pkgs; [
            nix
            git
          ];
      } // extraConfig;
    };

    # Test script to verify the setup
    testScript = ''
    start_all()
    
    cache.wait_for_unit("nginx")
    cache.wait_for_open_port(80)
    
    ${name}.wait_for_unit("network.target")
    ${name}.succeed("ping -c 1 cache.local")

    # TODO: run test script
    # using specific trust model
    '';
  };
in {
  # Full local reproducibility model - trusts only itself
  fullReproVM = makeTest "full-local-repro" {
    extraConfig.nix.settings = {
        substituters = [ ];
        trusted-public-keys = [ ];
    };
  };

  # Trusted infrastructure model - trusts central cache
  trustedInfraVM = makeTest "trusted-infra" {
    extraConfig.nix.settings = {
        substituters = [ "http://cache.local" ];
        trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
    };
  };

  # Distributed trust model - requires multiple builder agreement
  distributedTrustVM = makeTest "distributed-trust" {
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
    };
}