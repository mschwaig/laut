{
  system,
  laut,
  pkgs,
  nixpkgs-under-test,
  lib,
  verifierExtraConfig,
  ...
}:
# `imports` rather than `lib.recursiveUpdate` so list-typed options like
# `environment.systemPackages` get *merged* by the NixOS module system instead
# of being silently overwritten when a test pulls in extra packages.
{
  imports = [ verifierExtraConfig ];
  config = {
      virtualisation.memorySize = 2 * 1024;
      virtualisation.cores = 2;
      virtualisation.writableStore = true;
      virtualisation.useNixStoreImage = true;
      systemd.services.nix-daemon.enable = true;
      virtualisation.mountHostNixStore = false;

      nix = {
        # Match the builder: both sides instantiate the under-test drv tree
        # via the same Nix implementation. Lix and CppNix can disagree on
        # the resulting drv hashes deep in a large tree (different bytecode
        # / hashing edge cases), which leaves the verifier asking the cache
        # for paths the builder never produced.
        package = pkgs.nix;
        checkConfig = false;
        nixPath = [
          # Same shape as the builder's: both `<nixpkgs>` and `<nixpkgs-ca>`
          # point at the pinned under-test source so the verifier instantiates
          # the same drv tree the builder signed.
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
          experimental-features = nix-command flakes ca-derivations
          flake-registry = ${emptyRegistry}
        '';
      };

      environment.systemPackages = [
        pkgs.nix
        pkgs.git
        laut
      ];
    };
}
