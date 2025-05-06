{
  buildPythonPackage,
  python,
  pytestCheckHook,
  rustPlatform,
}:

buildPythonPackage {
  pname = "lautr";
  version = "0.2.0";

  src = ../datalog;

  pyproject = true;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../datalog/Cargo.lock;
    outputHashes = {
      "nix-compat-0.1.0" = "sha256-vSC6VxiRCtscfPuhejivMtinZXuj5tin9Mr7XW5cgJs=";
    };
  };

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
  ];

  pythonImportsCheck = [ "lautr" ];
}
