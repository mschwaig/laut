{
  system,
  nixpkgs,
  lib,
  pkgsIA,
  testName,
  cachePort ? 9000,
  cacheStoreUrl ? "s3://binary-cache?endpoint=http://cache:${builtins.toString cachePort}&region=eu-west-1",
  packageToBuild,
  verifierExtraConfig ? {},
  isMemoryConstrained ? false,
  needsExtraTime ? false,
  needsImpure ? false,
  testScriptFile,
  binaryCacheData? "",
  ...
}@args:

let
  fullArgs = {
    inherit cacheStoreUrl cachePort verifierExtraConfig;
    cacheAccessKey = "BKIKJAA5BMMU2RHO6IBB";
    cacheSecretKey = "V7f1CwQqAcwo80UEIJEjc5gVQUSSx5ohQ9GSrr12";
  } // args;
  testLib =  import (nixpkgs + "/nixos/lib/testing-python.nix") { inherit system; };
  packageToBuildStr = lib.concatStringsSep "." packageToBuild;
  test =  testLib.runTest ({
      name = "laut-${testName}";

      nodes = {
        cache = import ./machines/cache.nix (fullArgs);

        builderA = import ./machines/builder.nix (fullArgs // { 
          builderPublicKey = ../testkeys/builderA_key.public;
          builderPrivateKey = ../testkeys/builderA_key.private;
          nixPackage = pkgsIA.nix;
        });

        builderB = import ./machines/builder.nix (fullArgs // {
          builderPublicKey = ../testkeys/builderB_key.public;
          builderPrivateKey = ../testkeys/builderB_key.private;
          nixPackage = pkgsIA.nix;
        });

        verifier = import ./machines/verifier.nix (fullArgs);

        # TODO: add nixpkgs-mirror;
    };

    testScript = ''
        cachePort = ${builtins.toString cachePort}
        cacheAccessKey = "${fullArgs.cacheAccessKey}"
        cacheSecretKey = "${fullArgs.cacheSecretKey}"
        packageToBuild = "${packageToBuildStr}"
        cacheStoreUrl = "${cacheStoreUrl}"
        isMemoryConstrained = ${if isMemoryConstrained then "True" else "False"}
        builderA_pub = "${../testkeys/builderA_key.public}"
        builderB_pub = "${../testkeys/builderB_key.public}"
        binaryCacheData = "${binaryCacheData}"

        ${builtins.readFile testScriptFile}
      '';
} // (if needsExtraTime then {
    # Set timeout to 8 hours for large VM tests
    extraDriverArgs = ["--global-timeout=28800"];
  } else { }));
  # Apply __impure to both test and driver when needed
  # We need to:
  # 1. Make the driver impure (so it can depend on impure sign test)
  # 2. Make the test impure AND use the impure driver
  impureDriver = test.driver.overrideAttrs (_: { __impure = true; });
  impureDriverInteractive = test.driverInteractive.overrideAttrs (_: { __impure = true; });
  impureTest = test.config.rawTestDerivation.overrideAttrs (old: {
    __impure = true;
    # Replace the original driver reference with the impure driver in buildCommand
    buildCommand = builtins.replaceStrings
      [ "${test.driver}" ]
      [ "${impureDriver}" ]
      old.buildCommand;
  });
  testWithImpure = if needsImpure then
    impureTest // {
      driver = impureDriver;
      driverInteractive = impureDriverInteractive;
      # Preserve other useful attributes from original test
      inherit (test) config nodes meta;
    }
  else test;
in
  testWithImpure
