{
  lib,
  pkgs,
  fetchgit,
  rustPlatform,
  makeWrapper,
  difftastic,
  sign-only ? false,
}:
let
  snix-hash = "sha256-UcHOQmNKzhzw+8IbO86fGbiQFfwityudeV8K9E23dT4=";
  snix = fetchgit {
    url = "https://github.com/mschwaig/snix";
    rev = "21e90c2dae1827bb98963279d020b3009e032a21";
    hash = snix-hash;
  };

  # In sign-only mode, exclude rust/lautr-verify/ from the source tree entirely
  # so that edits to verification-only Rust code don't change the derivation hash.
  # The accompanying postPatch drops lautr-verify from the workspace and from
  # the laut binary crate's Cargo.toml so the remaining crates still resolve.
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
  rustPlatform.buildRustPackage {
    pname = if sign-only then "laut-sign-only" else "laut";
    version = "0.2.0";

    src = rustSrc;

    cargoLock = {
      lockFile = ../rust/Cargo.lock;
      outputHashes = {
        "laut-compat-0.1.0" = snix-hash;
        "wu-manber-0.1.0" = "sha256-7YIttaQLfFC/32utojh2DyOHVsZiw8ul/z0lvOhAE/4=";
      };
    };

    PROTO_ROOT = snix;

    nativeBuildInputs = [
      pkgs.protobuf
    ] ++ lib.optionals (!sign-only) [
      makeWrapper
    ];

    # Strip lautr-verify out of the workspace and out of the laut binary's
    # manifest so cargo can resolve the workspace without the (excluded)
    # lautr-verify dir. Kept as literal substitutions on purpose: if someone
    # reformats the affected lines, this fails loudly rather than silently
    # producing a build that still pulls in the verification code.
    postPatch = lib.optionalString sign-only ''
      substituteInPlace Cargo.toml \
        --replace-fail '    "lautr-verify",
' ""

      substituteInPlace laut/Cargo.toml \
        --replace-fail 'default = ["verify"]' 'default = []' \
        --replace-fail 'verify = ["dep:lautr-verify"]
' "" \
        --replace-fail 'lautr-verify = { path = "../lautr-verify", optional = true }
' ""
    '';

    cargoBuildFlags = lib.optionals sign-only [ "--no-default-features" ];

    # Integration tests reference fixtures under the repo's `tests/data/`,
    # which isn't part of the Rust source root. Skip the check phase here;
    # `cargo test --workspace` in the dev shell covers it, and the VM tests
    # exercise the binary end-to-end.
    doCheck = false;

    postInstall = lib.optionalString (!sign-only) ''
      wrapProgram $out/bin/laut \
        --prefix PATH : ${lib.makeBinPath [ difftastic ]}
    '';
  }
