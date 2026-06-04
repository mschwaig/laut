{
  lib,
  pkgs,
  fetchgit,
  buildPythonPackage,
  rustPlatform,
  sign-only ? false,
}:
let
  snix-hash = "sha256-pDe6ZiimQfxmNSDdemzshh0i9LyuUw3Lr6gjxMxUu+E=";
  snix = fetchgit {
    url = "https://github.com/mschwaig/snix";
    rev = "1715bb275f345b745888554edd475c233331a99c";
    hash = snix-hash;
  };

  # In sign-only mode, exclude rust/lautr-verify/ from the source tree entirely
  # so that edits to verification-only Rust code don't change the derivation hash.
  # The accompanying postPatch drops lautr-verify from the workspace and from
  # lautr-py's Cargo.toml so the remaining crates still resolve.
  rustSrc =
    let fs = lib.fileset; in
    if sign-only then
      fs.toSource {
        root = ../rust;
        fileset = fs.difference ../rust ../rust/lautr-verify;
      }
    else
      ../rust;
in
  buildPythonPackage {
    pname = if sign-only then "lautr-sign-only" else "lautr";
    version = "0.2.0";

    src = rustSrc;

    pyproject = true;
    cargoDeps = rustPlatform.importCargoLock {
      lockFile = ../rust/Cargo.lock;
      outputHashes = {
        "laut-compat-0.1.0" = snix-hash;
        "wu-manber-0.1.0" = "sha256-7YIttaQLfFC/32utojh2DyOHVsZiw8ul/z0lvOhAE/4=";
      };
    };

    PROTO_ROOT = snix;

    nativeBuildInputs = with rustPlatform; [
      cargoSetupHook
      maturinBuildHook
      pkgs.protobuf
    ];

    # Strip lautr-verify out of the workspace and out of lautr-py's manifest so
    # cargo can resolve the workspace without the (excluded) lautr-verify dir.
    # Kept as literal substitutions on purpose: if someone reformats the
    # affected lines, this fails loudly rather than silently producing a build
    # that still pulls in the verification code.
    postPatch = lib.optionalString sign-only ''
      substituteInPlace Cargo.toml \
        --replace-fail '    "lautr-verify",
' ""

      substituteInPlace lautr-py/Cargo.toml \
        --replace-fail 'default = ["verify"]' 'default = []' \
        --replace-fail 'verify = ["dep:lautr-verify"]
' "" \
        --replace-fail 'lautr-verify = { path = "../lautr-verify", optional = true }
' ""
    '';

    maturinBuildFlags = lib.optionals sign-only [ "--no-default-features" ];

    pythonImportsCheck = [ "lautr" ];
  }
