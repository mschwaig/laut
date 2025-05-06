{
  system,
  laut-sign-only,
  nixpkgs,
  lib,
  pkgsIA,
  pkgsCA,
  nixpkgs-swh,
  packageToBuild,
  builderPublicKey,
  builderPrivateKey,
  cacheStoreUrl,
  cacheAccessKey,
  cacheSecretKey,
  ...
}:

let
  # use infra built for collaboration with software heritage foundation
  # to find fixed output derivations
  # so we can make them available ahead of time
  # and run the tests without network access
  nixpkgs-swh-patched = pkgsIA.applyPatches {
    name = "patch-swh-find-tarballs";
    src = nixpkgs-swh;
    patches = [ ../../patches/nixpkgs-swh/0001-make-find-tarballs.nix-return-drvs-and-be-pure.patch ];
  };
  findTarballFods = import (nixpkgs-swh-patched + "/scripts/find-tarballs.nix" );
  prefetchedSources = map (drv: drv.out.outPath) (findTarballFods { pkgs = pkgsIA; expr = lib.getAttrFromPath packageToBuild pkgsCA; });
in {
  virtualisation.memorySize = 1024 * 8;
  virtualisation.cores = 8;
  virtualisation.diskSize = 1024 * 4;
  virtualisation.writableStore = true;
  virtualisation.useNixStoreImage = true;
  systemd.services.nix-daemon.enable = true;
  virtualisation.mountHostNixStore = false;

  virtualisation.additionalPaths = prefetchedSources;

  nix = {
    package = pkgsIA.lix;
    nixPath = [
      "nixpkgs=${nixpkgs}"
      "nixpkgs-ca=${
        pkgsIA.writeTextFile {
          name = "nixpkgs-ca";
          destination = "/default.nix";
          text =
          ''
            { ... }@args:
            let
              pkgs = import <nixpkgs> (args // {
                config = args.config or { } // {
                  contentAddressedByDefault = true;
                };
              });
            in pkgs
          '';
        }
      }"
    ];
    extraOptions =
      let
        emptyRegistry = builtins.toFile "empty-flake-registry.json" ''{"flakes":[],"version":2}''; # TODO: check if I should remove this
      in
      ''
        experimental-features = nix-command flakes ca-derivations
        flake-registry = ${emptyRegistry}
      '';
    settings = {
      trusted-substituters = [ ];
      post-build-hook = pkgsIA.writeShellScript "copy-to-cache" ''
        set -eux
        set -f # disable globbing

        # Create a sanitized filename from the derivation path
        SAFE_DRV_NAME=$(basename "$DRV_PATH" | tr -dc '[:alnum:].-')
        LOG_FILE="$HOME/hooklog-$SAFE_DRV_NAME"

        # Redirect all output to both the console and the derivation-specific log file
        exec > >(tee -a "$LOG_FILE") 2>&1

        [ -n "$OUT_PATHS" ]
        [ -n "$DRV_PATH" ]

        echo Pushing "$OUT_PATHS" to ${cacheStoreUrl}
        printf "%s" "$OUT_PATHS" | xargs nix copy --to "${cacheStoreUrl}" --no-require-sigs
        printf "%s" "$DRV_PATH"^'*' | xargs nix copy --to "${cacheStoreUrl}" --secret-key-files /etc/nix/private-key

        laut --debug sign-and-upload "$DRV_PATH" --secret-key-file /etc/nix/private-key --to "${cacheStoreUrl}"
      '';
    };
  };

  environment = {
    variables = {
      AWS_ACCESS_KEY_ID = cacheAccessKey;
      AWS_SECRET_ACCESS_KEY = cacheSecretKey;
    };
    etc = {
      "nix/public-key".source = builderPublicKey;
      "nix/private-key".source = builderPrivateKey;
    };
    systemPackages = with pkgsIA; [
      lix
      git
      laut-sign-only
    ];
  };
}