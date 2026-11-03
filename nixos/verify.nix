{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.laut.verify;
  inherit (lib) mkOption types;

  # `name:base64-ed25519-public-key`, same format as Nix's trusted-public-keys.
  keyStr = types.strMatching "[^:]+:[A-Za-z0-9+/]{43}=";

  # Submodule checks accept any attrset, so each node kind is discriminated by
  # its tag field before `oneOf` picks it.
  node = tag: options: types.addCheck (types.submodule { inherit options; }) (v: v ? ${tag});

  trustModelType = types.oneOf [
    (node "key" { key = mkOption { type = keyStr; }; })
    (node "key_legacy" { key_legacy = mkOption { type = keyStr; }; })
    # This host's own signing key, which only exists at runtime.
    (node "local" { local = mkOption { type = types.enum [ true ]; }; })
    (node "threshold" {
      threshold = mkOption { type = types.ints.positive; };
      of = mkOption { type = types.nonEmptyListOf trustModelType; };
    })
  ];

  leafKeys =
    m:
    if m ? threshold then lib.concatMap leafKeys m.of
    else [ (m.key or m.key_legacy or "local") ];

  thresholdsInRange =
    m:
    !(m ? threshold) || (m.threshold <= lib.length m.of && lib.all thresholdsInRange m.of);

  hasLegacy = m: m ? key_legacy || (m ? threshold && lib.any hasLegacy m.of);

  # Mirrors `TrustModel::validate` in laut-verify/src/verifier.rs; the CLI
  # re-checks at runtime, this just fails `nixos-rebuild` early.
  legacyPlacementOk =
    m:
    if m ? key_legacy then false
    else if !(m ? threshold) then true
    else
      let
        legacyChildren = lib.filter (c: c ? key_legacy) m.of;
      in
      (legacyChildren == [ ] || m.threshold == 1)
      && lib.all (c: !(c ? threshold) || !hasLegacy c) m.of;

  keys = leafKeys cfg.trustModel;

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

  configFile = pkgs.writeText "laut-verify.json" (builtins.toJSON {
    inherit caches;
    trust_model = toSpec cfg.trustModel;
  });
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
        assertion = signEnabled || !(lib.elem "local" keys);
        message = "services.laut.verify.trustModel: a `local` leaf needs `services.laut.sign` enabled on this host.";
      }
      {
        assertion = thresholdsInRange cfg.trustModel;
        message = "services.laut.verify.trustModel: every threshold must be <= the number of its `of` children.";
      }
      {
        assertion = lib.allUnique keys;
        message = "services.laut.verify.trustModel: a key may appear in at most one leaf.";
      }
      {
        assertion = legacyPlacementOk cfg.trustModel;
        message = "services.laut.verify.trustModel: key_legacy is only allowed as a direct child of a top-level `threshold = 1`.";
      }
    ];

    environment = {
      # Wins over the sign module's `laut-sign-only`, which also ships `bin/laut`.
      systemPackages = [ (lib.hiPrio cfg.package) ];
      etc."laut/verify.json".source = configFile;
    };
  };
}
