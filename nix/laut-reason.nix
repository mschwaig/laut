{
  buildPythonPackage,
  python,
  pytestCheckHook,
  rustPlatform,
}:

buildPythonPackage {
  pname = "laut_reason";
  version = "0.2.0";

  src = ../datalog;

  pyproject = true;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../datalog/Cargo.lock;
  };

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
  ];

  pythonImportsCheck = [ "laut_reason" ];
}
