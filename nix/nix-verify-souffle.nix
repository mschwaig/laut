{
  buildPythonApplication,
  python,
  hatchling,
  souffle,
}:

buildPythonApplication {
  pname = "nix_verify_souffle";
  version = "0.1.0";

  src = ../datalog;

  format = "other";
  build-system = [
    hatchling
  ];
  nativeBuildInputs = [
    souffle
  ];

  pythonImportsCheck = [ "nix_verify_souffle" ];
  doCheck = true;

  buildPhase = ''
    runHook preBuild
    souffle -o nix_verify_souffle $src/nix_verify.dl
    souffle -s python $src/nix_verify.dl
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    PKGS_PATH=$out/${python.sitePackages}/nix_verify_souffle
    mkdir -p $out/bin $PKGS_PATH
    cp nix_verify_souffle $out/bin/
    touch $PKGS_PATH/__init__.py
    cp SwigInterface.py $PKGS_PATH/SwigInterface.py
    cp _SwigInterface.so $PKGS_PATH/_SwigInterface.so
    runHook postInstall
  '';
}
