{
  system,
  laut,
  nixpkgs,
  nixpkgs-for-ca,
  lib,
  pkgsIA,
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
        package = pkgsIA.lix;
        checkConfig = false;
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
                  pkgs = import ${nixpkgs-for-ca} (args // {
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

      environment.systemPackages = with pkgsIA; [
        lix
        git
        laut
      ];
    };
}
