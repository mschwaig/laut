{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.laut.verify;
  inherit (lib) mkOption types;

  # Submodule checks accept any attrset, so each node kind is discriminated by
  # its tag field before `oneOf` picks it.
  node = tag: options: types.addCheck (types.submodule { inherit options; }) (v: v ? ${tag});

  trustModelType = types.oneOf [
    (node "key" { key = mkOption { type = types.str; }; })
    (node "key_legacy" { key_legacy = mkOption { type = types.str; }; })
    # This host's own signing key, which only exists at runtime.
    (node "local" { local = mkOption { type = types.enum [ true ]; }; })
    (node "threshold" {
      threshold = mkOption { type = types.ints.positive; };
      of = mkOption { type = types.nonEmptyListOf trustModelType; };
    })
  ];

  hasLocal = m: m.local or false || (m ? threshold && lib.any hasLocal m.of);

  # Traces this host signs itself (e.g. a `local` key) are verifiable too.
  # `or false`: the sign module may not be imported (`nixosModules.laut-verify`).
  signEnabled = config.services.laut.sign.enable or false;
  caches = lib.unique (cfg.caches ++ lib.optional signEnabled config.services.laut.sign.cacheUrl);

  # `local` is Nix-side sugar for the sign module's public key file.
  toSpec =
    m:
    if m.local or false then { key_file = config.services.laut.sign.publicKeyFile; }
    else if m ? threshold then m // { of = map toSpec m.of; }
    else m;

  # Validated by laut itself at build time, so a bad trust model fails
  # `nixos-rebuild` rather than `laut verify`.
  configFile =
    pkgs.runCommand "laut-verify.json"
      {
        nativeBuildInputs = [ cfg.package ];
        json = builtins.toJSON {
          inherit caches;
          trust_model = toSpec cfg.trustModel;
        };
        passAsFile = [ "json" ];
      }
      ''
        laut verify --check-config --config "$jsonPath"
        cp "$jsonPath" "$out"
      '';
in
{
  options.services.laut.verify = {
    enable = lib.mkEnableOption "laut build-trace verification";

    package = mkOption {
      type = types.package;
      default = pkgs.laut or (import ../default.nix { inherit pkgs; }).laut;
      defaultText = lib.literalExpression "pkgs.laut";
      description = ''
        The laut package to use. This contains both signing and
        verification code (the full build).
      '';
    };

    caches = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "https://cache.example.org" ];
      description = ''
        Signature caches (`http(s)://` or `file://`) to query during
        verification. If `services.laut.sign` is enabled on this host, its
        `cacheUrl` is queried as well.
      '';
    };

    trustModel = mkOption {
      type = trustModelType;
      default = { local = true; };
      example = lib.literalExpression ''
        {
          threshold = 2;
          of = [
            { key = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
            { key = "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="; }
          ];
        }
      '';
      description = ''
        Trust model: a `{ key = "name:base64"; }` leaf, a
        `{ key_legacy = "name:base64"; }` leaf (only as a direct child of a
        top-level `threshold = 1`), a `{ local = true; }` leaf (this host's
        own key from `services.laut.sign`), or
        `{ threshold = n; of = [ ... ]; }`. Each key may appear in at most
        one leaf.

        The default trusts only this host's own builds, so enabling both
        `services.laut.sign` and `services.laut.verify` works without
        further configuration.

        Written together with `caches` to `/etc/laut/verify.json`, which
        `laut verify` reads by default.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = caches != [ ];
        message = "services.laut.verify: set `caches` or enable `services.laut.sign` on this host.";
      }
      {
        assertion = signEnabled || !(hasLocal cfg.trustModel);
        message = "services.laut.verify.trustModel: a `local` leaf needs `services.laut.sign` enabled on this host.";
      }
    ];

    environment = {
      # Wins over the sign module's `laut-sign-only`, which also ships `bin/laut`.
      systemPackages = [ (lib.hiPrio cfg.package) ];
      etc."laut/verify.json".source = configFile;
    };
  };
}
