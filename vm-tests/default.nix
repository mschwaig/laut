{
  system ? "x86_64-linux",
  scope ? pkgsIA.callPackage ../default.nix { },
  laut ? scope.laut,
  laut-sign-only ? scope.laut-sign-only,
  nixpkgs,
  nixpkgs-for-ca,
  lib ? pkgsIA.lib,
  pkgsIA ? import nixpkgs { inherit system; },
  pkgsCA ? import nixpkgs-for-ca {
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
    inherit system scope laut laut-sign-only nixpkgs nixpkgs-for-ca lib pkgsIA pkgsCA nixpkgs-swh;
    verifierExtraConfig = {};
  } // args;
  makeTestSet = {
    name,
    addressing,             # "ca" | "ia"
    packageToBuild,
    fodScanPackage ? packageToBuild,
    isLarge ? false,
    isMemoryConstrained ? false
  }:
  let
    fullName = "${name}-${addressing}";
    namef = name: part: "${name}-${part}${
      if isMemoryConstrained then "-mem-constrained" else ""
    }";
    sign-test-name = namef fullName "sign";
    verify-test-name = namef fullName "verify";
    common = fullArgs // {
      inherit isMemoryConstrained packageToBuild fodScanPackage addressing;
      needsExtraTime = isLarge;
    };
    sign-test = import ./test-template.nix ({
        testName = sign-test-name;
        testScriptFile = ./sign-script.py;
    } // common);
  in {
    ${sign-test-name} = sign-test;

    ${verify-test-name} = import ./test-template.nix ( {
        testName = verify-test-name;
        testScriptFile = ./verify-script.py;
        binaryCacheData = "${sign-test}/cache";
      } // common);
  };
  smallPackageToBuild = (flattenList (lib.lists.replicate 7 [ "stdenv" "__bootPackages" ])) ++ [ "binutils" ];
  mediumPackageToBuild = (flattenList (lib.lists.replicate 4 [ "stdenv" "__bootPackages" ])) ++ [ "binutils" ];
  largePackageToBuild = [ "hello" ];
  smallCaSet = makeTestSet {
    name = "small"; addressing = "ca";
    packageToBuild = smallPackageToBuild;
    isLarge = false; isMemoryConstrained = false;
  };
  smallIaSet = makeTestSet {
    name = "small"; addressing = "ia";
    packageToBuild = smallPackageToBuild;
    isLarge = false; isMemoryConstrained = false;
  };
  mediumCaSet = makeTestSet {
    name = "medium"; addressing = "ca";
    packageToBuild = mediumPackageToBuild;
    # this is necessary because some FODs involved in the bootstrap
    # are easier to discover later in the bootstrap
    fodScanPackage = [ "hello" ];
    isLarge = true; isMemoryConstrained = false;
  };
  mediumIaSet = makeTestSet {
    name = "medium"; addressing = "ia";
    packageToBuild = mediumPackageToBuild;
    fodScanPackage = [ "hello" ];
    isLarge = true; isMemoryConstrained = false;
  };
  largeCaSet = makeTestSet {
    name = "large"; addressing = "ca";
    packageToBuild = largePackageToBuild;
    isLarge = true; isMemoryConstrained = false;
  };
  largeIaSet = makeTestSet {
    name = "large"; addressing = "ia";
    packageToBuild = largePackageToBuild;
    isLarge = true; isMemoryConstrained = false;
  };
  smallCaSign = smallCaSet."small-ca-sign";
in
  smallCaSet // smallIaSet // mediumCaSet // mediumIaSet // largeCaSet // largeIaSet // {
    # Exercises the hash-divergence debug probe end-to-end: reuses the
    # small-ca-sign cache (preimages on), tampers one trace's preimage with a
    # known marker on the verifier, then runs `laut verify
    # --debug-preimage-corpus file://...` and asserts difft surfaces the
    # marker. CA-only for now; an IA analog can come later alongside other
    # out-of-scope IA followups.
    #
    # The verifierExtraConfig injects just-this-test-needs-it tooling:
    # difftastic for the structural diff, and a writePython3Bin-wrapped
    # tamper helper that becomes a PATH-accessible `tamper-preimage` command.
    debug-probe = import ./test-template.nix (fullArgs // {
      testName = "debug-probe";
      testScriptFile = ./debug-probe-script.py;
      binaryCacheData = "${smallCaSign}/cache";
      packageToBuild = smallPackageToBuild;
      addressing = "ca";
      isMemoryConstrained = false;
      needsExtraTime = false;
      verifierExtraConfig = {
        environment.systemPackages = [
          pkgsIA.difftastic
          (pkgsIA.writers.writePython3Bin "tamper-preimage" { } (
            builtins.readFile ./tamper-preimage.py
          ))
        ];
      };
    });
  }

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
