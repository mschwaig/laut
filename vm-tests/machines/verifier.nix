{
  system,
  laut,
  nixpkgs,
  lib,
  pkgsIA,
  verifierExtraConfig,
  ...
}:
 (lib.recursiveUpdate ({
      virtualisation.memorySize = 2 * 1024;
      virtualisation.cores = 2;
      virtualisation.writableStore = true;
      virtualisation.useNixStoreImage = true;
      systemd.services.nix-daemon.enable = true;
      virtualisation.mountHostNixStore = false;

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
      };

      environment.systemPackages = with pkgsIA; [
        lix
        git
        laut
      ];
    }) verifierExtraConfig)
