{
  buildPythonPackage,
  protobuf,
  python,
  pytestCheckHook,
  rustPlatform,
}:

buildPythonPackage {
  pname = "lautr";
  version = "0.2.0";

  src = ../rust;

  pyproject = true;

  PROTOC = "${protobuf}/bin/protoc-29.4.0";

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../rust/Cargo.lock;
    outputHashes = {
      "laut-compat-0.1.0" = "sha256-KjiJNlbQA2KhyVFTSVLA4P31WIx8Fyy3jn+WwBJWE+4=";
      "wu-manber-0.1.0" = "sha256-7YIttaQLfFC/32utojh2DyOHVsZiw8ul/z0lvOhAE/4=";
    };
  };

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
    protobuf
  ];


  pythonImportsCheck = [ "lautr" ];
}
