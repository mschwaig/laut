{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.laut.verify;
in {
  options.services.laut.verify = {
    enable = lib.mkEnableOption "laut build-trace verification";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.laut or (import ../default.nix { inherit pkgs; }).laut;
      defaultText = lib.literalExpression "pkgs.laut";
      description = ''
        The laut package to use. This contains both signing and
        verification code (the full build).
      '';
    };

    caches = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = [ "http://cache.example.org:9000" ];
      description = ''
        URLs of HTTP signature caches to query during verification.
        Maps to repeatable `--cache` flags.
      '';
    };

    trustModel = lib.mkOption {
      type = lib.types.attrs;
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
        Declarative trust model as a Nix attrset. This is written to a
        Nix file at `/etc/laut/trust-model.nix` and passed to `laut verify`
        via the `--trust-model-config` flag (and the
        `LAUT_TRUST_MODEL_CONFIG` environment variable on the wrapper).

        Keys are referenced inline as `name:base64-public-key` strings.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment = {
      systemPackages = [ cfg.package ]
        ++ lib.optional (cfg.caches != []) (
          pkgs.writeShellScriptBin "laut-verify" ''
            exec ${cfg.package}/bin/laut verify \
              ${lib.concatMapStrings (c: ''--cache "${c}" '') cfg.caches}\
              --trust-model-config /etc/laut/trust-model.nix \
              "$@"
          ''
        );

      etc."laut/trust-model.nix".source = pkgs.writeText "laut-trust-model.nix"
        (lib.generators.toPretty { } cfg.trustModel);
    };
  };
}
