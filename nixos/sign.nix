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
  keyFile = lib.defaultTo "${stateDir}/local.key" cfg.secretKeyFile;

  # Unique tmp name: parallel post-build hooks may run this concurrently.
  derivePublicKey = ''
    tmp=$(mktemp "${cfg.publicKeyFile}.XXXXXX")
    ${nix} key convert-secret-to-public < "${keyFile}" > "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "${cfg.publicKeyFile}"
  '';
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

        If null, a key named `local` is generated in `${stateDir}/local.key`
        on first boot.
      '';
    };

    publicKeyFile = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "${stateDir}/local.key.public";
      description = ''
        Public half of the signing key, derived at boot and before every
        signing, so it follows a rotated `secretKeyFile`. This is the key a
        `{ local = true; }` leaf in `services.laut.verify.trustModel` stands
        for.
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
    systemd.services.laut-keygen = {
      description = "Prepare laut signing key";
      wantedBy = [ "multi-user.target" "nix-daemon.service" ];
      before = [ "nix-daemon.service" ];
      serviceConfig = {
        Type = "oneshot";
        StateDirectory = "laut";
      };
      script = ''
        ${lib.optionalString (cfg.secretKeyFile == null) ''
          if [ ! -e "${keyFile}" ]; then
            (umask 077; ${nix} key generate-secret --key-name local > "${keyFile}.tmp")
            mv "${keyFile}.tmp" "${keyFile}"
          fi
        ''}
        ${derivePublicKey}
      '';
    };

    nix.settings.post-build-hook = lib.mkDefault (pkgs.writeShellScript "laut-post-build-hook" ''
      set -eux
      set -f # disable globbing

      [ -n "$OUT_PATHS" ]
      [ -n "$DRV_PATH" ]

      # Follow secret-manager key rotation.
      if [ "${keyFile}" -nt "${cfg.publicKeyFile}" ]; then
        ${derivePublicKey}
      fi

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
