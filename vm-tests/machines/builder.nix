{
  system,
  laut-sign-only,
  pkgs,
  nixpkgs-under-test,
  lib,
  pkgsIA,
  pkgsCA,
  nixpkgs-swh,
  packageToBuild,
  fodScanPackage ? packageToBuild,
  builderPublicKey,
  builderPrivateKey,
  cacheStoreUrl,
  nixPackage ? pkgs.nix,
  experiment ? null,
  ...
}:

let
  # Use infra built for collaboration with Software Heritage Foundation
  # to find fixed-output derivations via expression-level traversal.
  # This finds most FODs but misses some hidden behind passthru attributes.
  #
  # Walk pkgsIA — pkgsIA and pkgsCA derive from the same pinned commit, so
  # their FOD outputs agree (FODs are content-addressed by declared hash
  # regardless of `contentAddressedByDefault`). Picking either is fine.
  nixpkgs-swh-patched = pkgs.applyPatches {
    name = "patch-swh-find-tarballs";
    src = nixpkgs-swh;
    patches = [ ../../patches/nixpkgs-swh/0001-make-find-tarballs.nix-return-drvs-and-be-pure.patch ];
  };
  findTarballFods = import (nixpkgs-swh-patched + "/scripts/find-tarballs.nix");
  autoDiscoveredFods = findTarballFods { pkgs = pkgsIA; expr = lib.getAttrFromPath fodScanPackage pkgsIA; };

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

  prefetchedFods = autoDiscoveredFods ++ supplementaryFods;
  prefetchedSources = map (drv: drv.out.outPath) prefetchedFods;
  # NixOS's initial store registration does not retain content addresses.
  # Keep the declared addressing information alongside the preloaded contents.
  prefetchedManifest = map (drv: {
    path = drv.out.outPath;
    ca = {
      method = if (drv.outputHashMode or "flat") == "recursive" then "nar" else "flat";
      hash = builtins.convertHash ({
        hash = drv.outputHash;
        toHashFormat = "sri";
      } // lib.optionalAttrs (drv.outputHashAlgo != null && drv.outputHashAlgo != "") {
        hashAlgo = drv.outputHashAlgo;
      });
    };
  }) prefetchedFods;
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
      # `<nixpkgs>` and `<nixpkgs-ca>` both resolve to the pinned
      # nixpkgs-under-test source; the latter wraps it with
      # `contentAddressedByDefault = true`. Same source = same FOD outputs,
      # so find-tarballs.nix (walked over pkgsIA above) discovers the same
      # things the in-VM build will request.
      "nixpkgs=${nixpkgs-under-test}"
      "nixpkgs-ca=${
        pkgs.writeTextFile {
          name = "nixpkgs-ca";
          destination = "/default.nix";
          text =
          ''
            { ... }@args:
            let
              pkgs = import ${nixpkgs-under-test} (args // {
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
        experimental-features = nix-command flakes ca-derivations${lib.optionalString (experiment != null) " store-path-seeding"}
        flake-registry = ${emptyRegistry}
      '';
    settings = lib.optionalAttrs (experiment != null) {
      store-path-seed = experiment.seed;
      eval-cache = false;
      substituters = [ ];
    } // {
      trusted-substituters = [ ];
      post-build-hook = pkgs.writeShellScript "copy-to-cache" ''
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
        upload_errors=()
        printf "%s" "$OUT_PATHS" | xargs nix copy --to "${cacheStoreUrl}" --no-require-sigs || upload_errors+=("content upload exited $?")
        printf "%s" "$DRV_PATH"^'*' | xargs nix copy --to "${cacheStoreUrl}" --secret-key-files /etc/nix/private-key || upload_errors+=("realization upload exited $?")

        sign_status=0
        laut sign-and-upload --include-preimage "$DRV_PATH" --secret-key-file /etc/nix/private-key --to "${cacheStoreUrl}" || sign_status=$?
        ${lib.optionalString (experiment != null) ''
          record_args=(--sign-status "$sign_status")
          for error in "''${upload_errors[@]}"; do
            record_args+=(--optional-failure "$error")
          done
          laut-experiment record "''${record_args[@]}"
        ''}
        test "''${#upload_errors[@]}" -eq 0
        exit "$sign_status"
      '';
    };
  };

  environment = {
    etc = {
      "nix/public-key".source = builderPublicKey;
      "nix/private-key".source = builderPrivateKey;
    } // lib.optionalAttrs (experiment != null) {
      "laut-experiment.json".text = builtins.toJSON experiment;
      "laut-prefetched-sources.json".text = builtins.toJSON prefetchedManifest;
    };
    systemPackages = [
      nixPackage
      pkgs.git
      laut-sign-only
    ] ++ lib.optionals (experiment != null) [
      (pkgs.writers.writePython3Bin "laut-experiment" { } (builtins.readFile ../experiment.py))
      (pkgs.writers.writePython3Bin "laut-seed-inputs" { } (builtins.readFile ../seed-inputs.py))
    ];
  };
}
