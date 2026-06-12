{
  system,
  pkgs,
  lib,
  pkgsIA,
  testName,
  cachePort ? 9000,
  cacheStoreUrl ? "http://cache:${builtins.toString cachePort}",
  packageToBuild,
  addressing,
  verifierExtraConfig ? {},
  isMemoryConstrained ? false,
  needsExtraTime ? false,
  testScriptFile,
  binaryCacheData? "",
  ...
}@args:

let
  fullArgs = {
    inherit cacheStoreUrl cachePort verifierExtraConfig;
  } // args;
  # `pkgs` is the infra Nix evaluator (rolling). We use its nixpkgs path to
  # locate the test-runner library, and its `nix` binary to drive the test
  # itself from inside the VM (writers / wrappers also come from here in
  # builder.nix and verifier.nix).
  testLib = import (pkgs.path + "/nixos/lib/testing-python.nix") { inherit system; };
  packageToBuildStr = lib.concatStringsSep "." packageToBuild;
  test =  testLib.runTest ({
      name = "laut-${testName}";

      nodes = {
        cache = import ./machines/cache.nix (fullArgs);

        builderA = import ./machines/builder.nix (fullArgs // {
          builderPublicKey = ../testkeys/builderA_key.public;
          builderPrivateKey = ../testkeys/builderA_key.private;
          nixPackage = pkgs.nix;
        });

        builderB = import ./machines/builder.nix (fullArgs // {
          builderPublicKey = ../testkeys/builderB_key.public;
          builderPrivateKey = ../testkeys/builderB_key.private;
          nixPackage = pkgs.nix;
        });

        verifier = import ./machines/verifier.nix (fullArgs);

        # TODO: add nixpkgs-mirror;
    };

    testScript = ''
        cachePort = ${builtins.toString cachePort}
        packageToBuild = "${packageToBuildStr}"
        cacheStoreUrl = "${cacheStoreUrl}"
        addressing = "${addressing}"
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
in
  test
