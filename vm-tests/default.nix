{
  system ? "x86_64-linux",
  scope ? pkgsIA.callPackage ../default.nix { },
  laut ? scope.laut,
  laut-sign-only ? scope.laut-sign-only,
  nixpkgs ? builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/4633a7c72337ea8fd23a4f2ba3972865e3ec685d.tar.gz";
    sha256 = "sha256:0z9jlamk8krq097a375qqhyj7ljzb6nlqh652rl4s00p2mf60f6r";
  },
  lib ? pkgsIA.lib,
  pkgsIA ? import nixpkgs { inherit system; },
  pkgsCA ? import nixpkgs {
    config.contentAddressedByDefault = true;
    inherit system;
  },
  nixpkgs-swh ? builtins.fetchTarball {
    url = "https://github.com/nix-community/nixpkgs-swh/archive/552356958e70967398072e085e50fc675243e5c1.tar.gz";
    sha256 = "1sxgwknm1a2yhb5njk2xl8lkyy600bcrra64m352gmdmilwjbd4s";
  },
  ...
}@args:
let
  flattenList = builtins.concatLists;
  fullArgs = {
    inherit system scope laut laut-sign-only nixpkgs lib pkgsIA pkgsCA nixpkgs-swh;
    verifierExtraConfig = {};
  } // args;
  makeTestSet = {
    name,
    packageToBuild,
    isLarge ? false,
    isMemoryConstrained ? false
  }:
  let
    namef = name: part: "${name}-${part}${
      if isMemoryConstrained then "-mem-constrained" else ""
    }";
    sign-test-name = namef name "sign";
    verify-test-name = namef name "verify";
    common = fullArgs // {
      inherit isMemoryConstrained packageToBuild;
      needsExtraTime = isLarge;
    };
    sign-test = import ./test-template.nix ({
        testName = sign-test-name;
        testScriptFile = ./sign-script.py;
    } // common);
  in rec {
    ${sign-test-name} = sign-test;

    ${verify-test-name} = import ./test-template.nix ( {
        testName = verify-test-name;
        testScriptFile = ./verify-script.py;
      } // common // (if isLarge then {
        # the large tests run only interactively
        binaryCacheData = "./data";
      } else {
        binaryCacheData = "${sign-test}/data";
    }));
  };
in
  ((makeTestSet {
    name = "small";
    packageToBuild = (flattenList (lib.lists.replicate 7 [ "stdenv" "__bootPackages" ])) ++ [ "binutils" ];
    isLarge = false;
    isMemoryConstrained = false;
  }) // (makeTestSet {
    name = "large";
    packageToBuild = [ "hello" ];
    isLarge = true;
    isMemoryConstrained = false;
  }) // (makeTestSet {
    name = "medium";
    packageToBuild = (flattenList (lib.lists.replicate 4 [ "stdenv" "__bootPackages" ])) ++ [ "binutils" ];
    isLarge = true;
    isMemoryConstrained = false;
  }))

  # Full local reproducibility model - trusts only itself
  #fullReproVM = import ./test-template.nix (fullArgs // {
  #  testName = "fullReproVM";
    # verifierExtraConfig.nix = {
    #   extraOptions = "experimental-features = nix-command flakes";
    #   settings = {
    #       substituters = [ ];
    #       trusted-public-keys = [ ];
    #   };
    # };
    #  trust_model = Builder(self())
#    });

  # Trusted infrastructure model - trusts central cache
  #trustedInfraVM = import ./test-template.nix (fullArgs // {
  #  testName = "trustedInfraVM";
  #  verifierExtraConfig = {
  #    nix = {
  #    extraOptions = "experimental-features = nix-command flakes";
  #    settings = {
  #      substituters = [ "http://cache.local" ];
  #      trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
  #    };
  #    };
      #  trust_model = threshold(1,
      #   Builder(self()),
      #   Signer("cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=", legacy=true))
 #   };});


  # Distributed trust model - requires multiple builder agreement
 # distributedTrustVM = import ./test-template.nix (fullArgs // {
 #   testName = "distributedTrustVM";
 #   verifierExtraConfig.nix = {
 #     extraOptions = "experimental-features = nix-command flakes";
 #     settings = {
 #       substituters = [
 #         "http://builder1.local"
 #         "http://builder2.local"
 #       ];
 #       trusted-public-keys = [
 #         "builder1.local:${placeholder "BUILDER1_KEY"}"
 #         "builder2.local:${placeholder "BUILDER2_KEY"}"
 #       ];
 #     };
      #  trust_model = threshold(2,
      #   Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU="),
      #   Builder("builderB:iN9OEB6nRfDK0Ae8fscfOZAjWPXn4CdIIHiaMwWxXQk="))
 #   };});

  #attestBuilder = import ./test-template.nix (fullArgs // {
  #  testName = "attestBuilder";
  #  verifierExtraConfig.nix = {
  #      extraOptions = "experimental-features = nix-command flakes";
  #      substituters = [ "http://cache.local" ];
  #      trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
  #    };
    #  trust_model = Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU=",
    #     sw_flake = "github:nixos/nixpkgs-builders/8d99dd5e331e9fc8f3480d739b709eafc1e4ceb6#amd-tpm-2.0",
    #     host_sw_criteria = SW_CRITERIA.TPM-2.0_STRICT,
    #     host_hw_criteria = HW_CRTIERIA.HP_MILAN_NO_PUBLIC_VULN,
    #     host_identity = "smRvhWX9+vVTe3gpNsAp4EuJmUtdw2Ih9xcp+Mjd+6g=",
    #     host_sw_exclude = SW_CRITERIA.DRVS_WITH_VULNS + nixpkgsRange("xyutils", "5.6.0", "5.6.1"))
  #});
