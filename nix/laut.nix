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
  lautr,
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
        fileset = fs.difference (fs.unions [
            ../src/laut
            ../tests
            ../testkeys
            ../pyproject.toml
            ../LICENSE.md
            ../README.md
          ]) (
            if sign-only then
              ../src/laut/verification
            else
              fs.unions []);
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

  preCheck = "";
  # do not depend on diffoscope for now because it is HUGE
  #  if sign-only then "" else
  #    ''
  #      export PATH=${lib.makeBinPath [ diffoscope ]}:$PATH
  #    '';

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
      #sigstore
      loguru
      lautr
    ];

  pythonImportsCheck = [ "laut" ];
}
