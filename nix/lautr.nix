{
  pkgs,
  fetchgit,
  buildPythonPackage,
  rustPlatform,
}:
let
  snix-hash = "sha256-pDe6ZiimQfxmNSDdemzshh0i9LyuUw3Lr6gjxMxUu+E=";
  snix = fetchgit {
    url = "https://github.com/mschwaig/snix";
    rev = "1715bb275f345b745888554edd475c233331a99c";
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
