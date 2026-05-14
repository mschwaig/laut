{
  system,
  laut-sign-only,
  nixpkgs,
  lib,
  pkgsIA,
  pkgsCA,
  nixpkgs-swh,
  packageToBuild,
  fodScanPackage ? packageToBuild,
  builderPublicKey,
  builderPrivateKey,
  cacheStoreUrl,
  nixPackage ? pkgsIA.nix,
  ...
}:

let
  # Use infra built for collaboration with Software Heritage Foundation
  # to find fixed-output derivations via expression-level traversal.
  # This finds most FODs but misses some hidden behind passthru attributes.
  nixpkgs-swh-patched = pkgsIA.applyPatches {
    name = "patch-swh-find-tarballs";
    src = nixpkgs-swh;
    patches = [ ../../patches/nixpkgs-swh/0001-make-find-tarballs.nix-return-drvs-and-be-pure.patch ];
  };
  findTarballFods = import (nixpkgs-swh-patched + "/scripts/find-tarballs.nix");
  autoDiscoveredFods = findTarballFods { pkgs = pkgsIA; expr = lib.getAttrFromPath fodScanPackage pkgsCA; };

  # FODs that find-tarballs never discovers (hidden in let-bindings
  # or behind inaccessible passthru paths).
  supplementaryFods = [
    (pkgsIA.fetchurl {
      name = "config.guess-948ae97";
      url = "https://git.savannah.gnu.org/cgit/config.git/plain/config.guess?id=948ae97ca5703224bd3eada06b7a69f40dd15a02";
      hash = "sha256-ZByuPAx0xJNU0+3gCfP+vYD+vhUBp3wdn6yNQsxFtss=";
    })
    (pkgsIA.fetchurl {
      name = "config.sub-948ae97";
      url = "https://git.savannah.gnu.org/cgit/config.git/plain/config.sub?id=948ae97ca5703224bd3eada06b7a69f40dd15a02";
      hash = "sha256-/jovMvuv9XhIcyVJ9I2YP9ZSYCTsLw9ancdcL0NZo6Y=";
    })
    pkgsIA.pkg-config-unwrapped.src
  ];

  prefetchedSources =
    map (drv: drv.out.outPath) autoDiscoveredFods
    ++ map (drv: drv.out.outPath) supplementaryFods;
in {
  virtualisation.memorySize = 1024 * 6;
  virtualisation.cores = 4;  # Reduced from 6 to lower peak memory usage during parallel GCC builds
  virtualisation.diskSize = 1024 * 4;
  virtualisation.writableStore = true;
  virtualisation.useNixStoreImage = true;
  systemd.services.nix-daemon.enable = true;
  virtualisation.mountHostNixStore = false;

  virtualisation.additionalPaths = prefetchedSources;

  nix = {
    package = nixPackage;
    # Do not check config to prevent the following error:
    # > Validating generated nix.conf
    # > error: The ca-derivations experimental feature is deprecated and will be removed in Lix 2.94. See https://git.lix.systems/lix-project/lix/issues/815 for more details.
    checkConfig = false;
    # see https://jade.fyi/blog/pinning-nixos-with-npins/ for an explanation
    # and how to do something similar with flakes
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
    etc = {
      "nix/public-key".source = builderPublicKey;
      "nix/private-key".source = builderPrivateKey;
    };
    systemPackages = with pkgsIA; [
      nixPackage
      git
      laut-sign-only
    ];
  };
}
