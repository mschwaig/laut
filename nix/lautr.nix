{
  pkgs,
  fetchgit,
  buildPythonPackage,
  rustPlatform,
}:
let
  snix-hash = "sha256-KjiJNlbQA2KhyVFTSVLA4P31WIx8Fyy3jn+WwBJWE+4=";
  snix = fetchgit {
    url = "https://github.com/mschwaig/snix";
    rev = "4311236e67a0026b946d4d509aafac18037721d7";
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
