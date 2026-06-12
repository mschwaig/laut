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
  snix-hash = "sha256-4rwptmXR4IhHIcR8B25z2YRSxKzO1/V63uHXuTgptZ4=";
  snix = fetchgit {
    url = "https://github.com/mschwaig/snix";
    rev = "497a8267cd36387f55305c76971168b538560ca2";
    hash = snix-hash;
  };

  # Explicit fileset: the repo root carries non-Rust files (nix/, vm-tests/,
  # docs, etc.) that don't belong in the build sandbox. In sign-only mode we
  # also exclude `laut-verify/` so edits to verification-only code don't change
  # the derivation hash. The accompanying postPatch drops `laut-verify` from
  # the workspace + from `laut-cli/Cargo.toml` so the remaining crates resolve.
  fs = lib.fileset;
  rustWorkspace = fs.unions [
    ../Cargo.toml
    ../Cargo.lock
    ../laut-cli
    ../laut-sign
    ../laut-verify
  ];
  rustSrc =
    fs.toSource {
      root = ../.;
      fileset =
        if sign-only then fs.difference rustWorkspace ../laut-verify
        else rustWorkspace;
    };
in
  rustPlatform.buildRustPackage {
    pname = if sign-only then "laut-sign-only" else "laut";
    version = "0.4.0";

    src = rustSrc;

    cargoLock = {
      lockFile = ../Cargo.lock;
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

    # Kept as literal substitutions on purpose: if someone reformats the
    # affected lines, this fails loudly rather than silently producing a
    # build that still pulls in the verification code.
    postPatch = lib.optionalString sign-only ''
      substituteInPlace Cargo.toml \
        --replace-fail '    "laut-verify",
' ""

      substituteInPlace laut-cli/Cargo.toml \
        --replace-fail 'default = ["verify"]' 'default = []' \
        --replace-fail 'verify = ["dep:laut-verify"]
' "" \
        --replace-fail 'laut-verify = { path = "../laut-verify", optional = true }
' ""
    '';

    cargoBuildFlags = lib.optionals sign-only [ "--no-default-features" ];

    # Integration tests reference fixtures under the repo's `tests/data/`,
    # which isn't part of the Rust source root. Skip the check phase here;
    # `cargo test --workspace` covers it, and the VM tests exercise the
    # binary end-to-end.
    doCheck = false;

    postInstall = lib.optionalString (!sign-only) ''
      wrapProgram $out/bin/laut \
        --prefix PATH : ${lib.makeBinPath [ difftastic ]}
    '';
  }
