{
  lib,
  buildPythonApplication,
  setuptools,
  setuptools-scm,
  pytestCheckHook,
  rfc8785,
  pyjwt,
  cryptography,
  boto3,
  click,
  sigstore,
  loguru,
  sign-only ? false,
  nix-verify-souffle,
}:

buildPythonApplication {
  pname = "laut";
  version = "0.1.0";
  pyproject = true;

  src =
    let
      fs = lib.fileset;
    in
    fs.toSource {
      root = ../.;
      fileset = fs.unions [
        ../src/laut
        ../tests
        ../testkeys
        ../pyproject.toml
        ../LICENSE.md
        ../README.md
      ];
    };

  build-system = [
    setuptools
    setuptools-scm
  ];

  postPatch =
    if sign-only then
      ''
        substituteInPlace "src/laut/build_config.py" \
          --replace-fail "sign_only = False" "sign_only = True"
      ''
    else
      "";

  nativeCheckInputs = (
    if sign-only then
      [ ]
    else
      [
        pytestCheckHook
      ]
  );

  dependencies =
    [
      rfc8785
      pyjwt
      cryptography
      boto3
      click
      sigstore
      loguru
    ]
    ++ (
      if sign-only then
        [ ]
      else
        [
          nix-verify-souffle
        ]
    );

  pythonImportsCheck = [ "laut" ];
}
