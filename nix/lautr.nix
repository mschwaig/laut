{
  pkgs,
  fetchgit,
  buildPythonPackage,
  rustPlatform,
}:
let
  snix-hash = "sha256-db2cocguvGrQqKQOEYtf2CqC8gh1XRPzEjXA2lCdup8=";
  snix = fetchgit {
    url = "https://github.com/mschwaig/snix";
    rev = "b1b380ff9cec6c9885083727a6bba3fb6b4a099d";
    hash = snix-hash;
  };
in
  buildPythonPackage {
    pname = "lautr";
    version = "0.2.0";

    src = ../rust;

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

    pythonImportsCheck = [ "lautr" ];
  }
