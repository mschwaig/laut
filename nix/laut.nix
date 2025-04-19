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
  diffoscope,
  sigstore,
  loguru,
  sign-only ? false,
  laut-reason,
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

  preCheck =
    if sign-only then "" else
      ''
        export PATH=${lib.makeBinPath [ diffoscope ]}:$PATH
      '';

  postInstall =
    if sign-only then "" else
      ''
        wrapProgram $out/bin/laut \
          --prefix PATH : ${lib.makeBinPath [ diffoscope ]}
      '';

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
          laut-reason
        ]
    );

  pythonImportsCheck = [ "laut" ];
}
