{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.laut.sign;
in {
  options.services.laut.sign = {
    enable = lib.mkEnableOption "laut build-trace signing via a Nix post-build hook";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.laut-sign-only or (import ../default.nix { inherit pkgs; }).laut-sign-only;
      defaultText = lib.literalExpression "pkgs.laut-sign-only";
      description = ''
        The laut-sign-only package to use. This contains only the signing
        side of laut (no verification code) and is what should run on
        builders.
      '';
    };

    cacheUrl = lib.mkOption {
      type = lib.types.str;
      example = "http://cache.example.org:9000";
      description = ''
        URL of the HTTP cache to upload signed traces and store paths to.
        This is the `--to` argument of `laut sign-and-upload`.
      '';
    };

    secretKeyFile = lib.mkOption {
      type = lib.types.path;
      example = "/etc/nix/laut/builder.key";
      description = ''
        Path to the Nix-format secret key file (`name:base64-private-key`).
        This key is used both for legacy narinfo signing (via
        `nix copy --secret-key-files`) and for laut trace signing.
      '';
    };

    publicKeyFile = lib.mkOption {
      type = lib.types.path;
      example = "/etc/nix/laut/builder.key.public";
      description = ''
        Path to the public key file corresponding to `secretKeyFile`.
        Currently informational; placed at `/etc/nix/public-key` for
        discoverability.
      '';
    };

    includePreimage = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Embed the resolved ATerm preimage in the signed JWS debug block.
        Test/dev only — production signers should keep this off so
        preimages never leak into shared caches.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment = {
      etc = {
        "nix/public-key".source = cfg.publicKeyFile;
        "nix/private-key".source = cfg.secretKeyFile;
      };
      systemPackages = [ cfg.package ];
    };

    nix.settings.post-build-hook = lib.mkDefault (pkgs.writeShellScript "laut-post-build-hook" ''
      set -eux
      set -f # disable globbing

      [ -n "$OUT_PATHS" ]
      [ -n "$DRV_PATH" ]

      echo Pushing "$OUT_PATHS" to ${cfg.cacheUrl}
      printf "%s" "$OUT_PATHS" | xargs nix copy --to "${cfg.cacheUrl}" --no-require-sigs
      printf "%s" "$DRV_PATH"^'*' | xargs nix copy --to "${cfg.cacheUrl}" --secret-key-files /etc/nix/private-key

      ${lib.optionalString cfg.includePreimage ''
        laut sign-and-upload --include-preimage "$DRV_PATH" \
          --secret-key-file /etc/nix/private-key \
          --to "${cfg.cacheUrl}"
      ''}${lib.optionalString (!cfg.includePreimage) ''
        laut sign-and-upload "$DRV_PATH" \
          --secret-key-file /etc/nix/private-key \
          --to "${cfg.cacheUrl}"
      ''}
    '');
  };
}
