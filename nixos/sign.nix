{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.laut.sign;
  nix = "${config.nix.package}/bin/nix --extra-experimental-features nix-command";
  stateDir = "/var/lib/laut";
  keyFile = lib.defaultTo cfg.generatedKeyFile cfg.secretKeyFile;
in {
  options.services.laut.sign = {
    enable = lib.mkEnableOption "laut build-trace signing via a Nix post-build hook";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.laut or (import ../default.nix { inherit pkgs; }).laut;
      defaultText = lib.literalExpression "pkgs.laut";
      description = "The laut package to use.";
    };

    cacheUrl = lib.mkOption {
      type = lib.types.str;
      default = "file://${stateDir}";
      example = "http://cache.example.org:9000";
      description = ''
        Where to put signed traces: an `http(s)://` cache, or a `file://`
        directory. The default keeps this host's traces locally, where
        `services.laut.verify` on the same host picks them up. This is the
        `--to` argument of `laut sign-and-upload`.
      '';
    };

    copyStorePaths = lib.mkOption {
      type = lib.types.bool;
      default = !lib.hasPrefix "file://" cfg.cacheUrl;
      defaultText = lib.literalExpression ''!lib.hasPrefix "file://" cacheUrl'';
      description = ''
        Also `nix copy` the built outputs and derivations to `cacheUrl`.
        Off for a local trace directory: the outputs are already in the
        local store.
      '';
    };

    secretKeyFile = lib.mkOption {
      # A string, not a path: a path literal would copy the key into the
      # world-readable Nix store.
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = lib.literalExpression "config.sops.secrets.laut-key.path";
      description = ''
        Runtime path to a Nix-format secret key file
        (`name:base64-private-key`) readable by the nix-daemon. Used both
        for narinfo signing (`nix copy --secret-key-files`) and for laut
        trace signing.

        Trust it by its public key, a `{ key = "name:base64"; }` leaf in
        `services.laut.verify.trustModel`.

        If null, `laut generate-key` creates a key named `local` at
        `generatedKeyFile` on first boot, which a `{ generated = true; }`
        leaf stands for.
      '';
    };

    generatedKeyFile = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      internal = true;
      default = "${stateDir}/local.key";
      description = ''
        Where the key is generated if `secretKeyFile` is null. Its public
        half is next to it, in `local.key.public`.
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
    environment.systemPackages = [ cfg.package ];

    # The post-build hook runs inside the nix-daemon, so the key must exist
    # before it starts.
    systemd.services.laut-keygen = lib.mkIf (cfg.secretKeyFile == null) {
      description = "Generate laut signing key";
      wantedBy = [ "multi-user.target" "nix-daemon.service" ];
      before = [ "nix-daemon.service" ];
      serviceConfig = {
        Type = "oneshot";
        StateDirectory = "laut";
        ExecStart = "${cfg.package}/bin/laut generate-key ${cfg.generatedKeyFile}";
      };
    };

    nix.settings.post-build-hook = lib.mkDefault (pkgs.writeShellScript "laut-post-build-hook" ''
      set -eux
      set -f # disable globbing

      [ -n "$OUT_PATHS" ]
      [ -n "$DRV_PATH" ]

      ${lib.optionalString cfg.copyStorePaths ''
        echo Pushing "$OUT_PATHS" to ${cfg.cacheUrl}
        printf "%s" "$OUT_PATHS" | xargs ${nix} copy --to "${cfg.cacheUrl}" --no-require-sigs
        printf "%s" "$DRV_PATH"^'*' | xargs ${nix} copy --to "${cfg.cacheUrl}" --secret-key-files "${keyFile}"
      ''}

      ${cfg.package}/bin/laut sign-and-upload ${lib.optionalString cfg.includePreimage "--include-preimage "}"$DRV_PATH" \
        --secret-key-file "${keyFile}" \
        --to "${cfg.cacheUrl}"
    '');
  };
}
