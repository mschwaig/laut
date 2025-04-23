{
  system,
  nixpkgs,
  lib,
  testName,
  cachePort ? 9000,
  cacheStoreUrl ? "s3://binary-cache?endpoint=http://cache:${builtins.toString cachePort}&region=eu-west-1",
  packageToBuild,
  verifierExtraConfig ? {},
  isSmallTest,
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
in
  testLib.runTest {
      name = "laut-${testName}";

      nodes = {
        cache = import ./machines/cache.nix (fullArgs);

        builderA = import ./machines/builder.nix (fullArgs // { 
          builderPublicKey = ../testkeys/builderA_key.public;
          builderPrivateKey = ../testkeys/builderA_key.private;
        });

        builderB = import ./machines/builder.nix (fullArgs // { 
          builderPublicKey = ../testkeys/builderA_key.public;
          builderPrivateKey = ../testkeys/builderA_key.private;
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
        isSmallTest = ${if isSmallTest then "True" else "False"}
        builderA_pub = "${../testkeys/builderA_key.public}"
        builderB_pub = "${../testkeys/builderB_key.public}"

        ${builtins.readFile ./test-script.py}
      '';
}