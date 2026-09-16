{ pkgs, fetchFromGitHub, fetchurl, buildGoModule }:
let
  # Test-only toolchain: the existing infra pin has Go 1.25.0, while this
  # Rekor release requires 1.25.8. Do not update the package-under-test pin.
  go = pkgs.go_1_25.overrideAttrs {
    version = "1.25.8";
    src = fetchurl {
      url = "https://go.dev/dl/go1.25.8.src.tar.gz";
      sha256 = "17n5ssl30clqr30xwnimh6im4slkx5c9l25adlzzxiva8jid9279";
    };
  };
  buildGo = buildGoModule.override { inherit go; };
  server = buildGo {
    pname = "laut-rekor-test-tools";
    version = "2.3.0";
    src = fetchFromGitHub {
      owner = "sigstore";
      repo = "rekor-tiles";
      rev = "v2.3.0";
      sha256 = "1cyqgr04hpj132bxq7rpr7qslvnxnf7nrxmf06qfjksmmi4bmdb1";
    };
    vendorHash = "sha256-YVN9vFXyVuDAzjLw8vvyBXcY+aRf/uZ2uKKRRhm2bLE=";
    subPackages = [ "cmd/rekor-server/posix" ];
    # Upstream suites may contact public services. Our VM tests provide their
    # own private log and independently exercise signing and verification.
    doCheck = false;
    postInstall = ''
      mv $out/bin/posix $out/bin/rekor-server
    '';
  };
  interop = buildGo {
    pname = "laut-sigstore-interop";
    version = "1.3.0";
    src = fetchFromGitHub {
      owner = "sigstore";
      repo = "sigstore-go";
      rev = "v1.3.0";
      sha256 = "0fg7wi3i0qfwsnkya1zxmh0mgwwlh1zlzwrlik84m9900p4m86ix";
    };
    vendorHash = "sha256-c+VWpciT9vVgvFuF0GhCIWaX6w4/gi95J/NG+ZX0wVU=";
    postPatch = ''
      install -Dm644 ${../vm-tests/sigstore-interop.go} cmd/laut-interop/main.go
    '';
    subPackages = [ "cmd/laut-interop" ];
    doCheck = false;
  };
in pkgs.symlinkJoin {
  name = "laut-rekor-test-tools";
  paths = [ server interop ];
  passthru = { inherit server interop; };
}
