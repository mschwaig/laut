{
  buildPythonPackage,
  python,
  pytestCheckHook,
  rustPlatform,
}:

buildPythonPackage {
  pname = "lautr";
  version = "0.2.0";

  src = ../rust;

  pyproject = true;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../rust/Cargo.lock;
    outputHashes = {
      "nix-compat-0.1.0" = "sha256-FsRKjSRobT52NCRSfPs9mUKP4SE17f1f6eyOOrsnXOU=";
    };
  };

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
  ];

  pythonImportsCheck = [ "lautr" ];
}
