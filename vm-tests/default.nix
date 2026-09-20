{
  system ? "x86_64-linux",
  # Infra Nix evaluator (rolling): builds laut, qemu, writers, the test
  # wrappers. Used wherever the VM tests need a Nix package to run *the test
  # infrastructure* — never the package-under-test.
  pkgs,
  # Pinned source of the package-under-test. Both `pkgsIA` and `pkgsCA` derive
  # from this so their FOD outputs agree, regardless of which the VM ends up
  # building from inside.
  nixpkgs-under-test,
  nix-seeded,
  nixSeededPackage,
  nixSeededPatches,
  scope ? pkgs.callPackage ../default.nix { },
  laut ? scope.laut,
  laut-sign-only ? scope.laut-sign-only,
  lib ? pkgs.lib,
  pkgsIA ? import nixpkgs-under-test { inherit system; },
  pkgsCA ? import nixpkgs-under-test {
    config.contentAddressedByDefault = true;
    inherit system;
  },
  nixpkgs-swh ? builtins.fetchTarball {
    url = "https://github.com/nix-community/nixpkgs-swh/archive/552356958e70967398072e085e50fc675243e5c1.tar.gz";
    sha256 = "1sxgwknm1a2yhb5njk2xl8lkyy600bcrra64m352gmdmilwjbd4s";
  },
  ...
}@args:
let
  flattenList = builtins.concatLists;

  fullArgs = {
    inherit system scope laut laut-sign-only pkgs nixpkgs-under-test lib pkgsIA pkgsCA nixpkgs-swh;
    verifierExtraConfig = {};
  } // args;
  makeTestSet = {
    name,
    addressing,             # "ca" | "ia"
    packageToBuild,
    fodScanPackage ? packageToBuild,
    isLarge ? false,
    isMemoryConstrained ? false
  }:
  let
    fullName = "${name}-${addressing}";
    namef = name: part: "${name}-${part}${
      if isMemoryConstrained then "-mem-constrained" else ""
    }";
    sign-test-name = namef fullName "sign";
    verify-test-name = namef fullName "verify";
    common = fullArgs // {
      inherit isMemoryConstrained packageToBuild fodScanPackage addressing;
      needsExtraTime = isLarge;
    };
    sign-test = import ./test-template.nix ({
        testName = sign-test-name;
        testScriptFile = ./sign-script.py;
    } // common);
  in {
    ${sign-test-name} = sign-test;

    ${verify-test-name} = import ./test-template.nix ( {
        testName = verify-test-name;
        testScriptFile = ./verify-script.py;
        binaryCacheData = "${sign-test}/cache";
      } // common);
  };
  smallPackageToBuild = (flattenList (lib.lists.replicate 7 [ "stdenv" "__bootPackages" ])) ++ [ "binutils" ];
  mediumPackageToBuild = (flattenList (lib.lists.replicate 4 [ "stdenv" "__bootPackages" ])) ++ [ "binutils" ];
  largePackageToBuild = [ "hello" ];
  # Each experiment is an independent sign run, not a composition of checks.
  makeEquivalenceSign = { id, addressing, seed ? "" }:
    let
      nixPackage = nixSeededPackage;
    in import ./test-template.nix (fullArgs // {
      testName = "${id}-sign";
      testScriptFile = ./sign-script.py;
      packageToBuild = smallPackageToBuild;
      inherit addressing nixPackage;
      # This manifest is also passed verbatim to builders as `experiment`.
      experiment = {
        inherit id addressing seed system;
        target = lib.concatStringsSep "." smallPackageToBuild;
        nixPackage = toString nixPackage;
        nixRevision = nix-seeded.rev;
        nixPatches = nixSeededPatches;
        nixpkgs = {
          source = toString nixpkgs-under-test;
          revision = nixpkgs-under-test.rev;
        };
        laut-sign-only = toString laut-sign-only;
      };
    });
  equivalenceSigns = lib.listToAttrs (map (variant: {
    name = "${variant.id}-sign";
    value = makeEquivalenceSign variant;
  }) [
    { id = "small-equivalence-ia"; addressing = "ia"; }
    { id = "small-equivalence-ia-seed-a"; addressing = "ia"; seed = "seed-a"; }
    { id = "small-equivalence-ia-seed-b"; addressing = "ia"; seed = "seed-b"; }
    { id = "small-equivalence-ca"; addressing = "ca"; }
  ]);
  smallCaSet = makeTestSet {
    name = "small"; addressing = "ca";
    packageToBuild = smallPackageToBuild;
    isLarge = false; isMemoryConstrained = false;
  };
  smallIaSet = makeTestSet {
    name = "small"; addressing = "ia";
    packageToBuild = smallPackageToBuild;
    isLarge = false; isMemoryConstrained = false;
  };
  mediumCaSet = makeTestSet {
    name = "medium"; addressing = "ca";
    packageToBuild = mediumPackageToBuild;
    # this is necessary because some FODs involved in the bootstrap
    # are easier to discover later in the bootstrap
    fodScanPackage = [ "hello" ];
    isLarge = true; isMemoryConstrained = false;
  };
  mediumIaSet = makeTestSet {
    name = "medium"; addressing = "ia";
    packageToBuild = mediumPackageToBuild;
    fodScanPackage = [ "hello" ];
    isLarge = true; isMemoryConstrained = false;
  };
  largeCaSet = makeTestSet {
    name = "large"; addressing = "ca";
    packageToBuild = largePackageToBuild;
    isLarge = true; isMemoryConstrained = false;
  };
  largeIaSet = makeTestSet {
    name = "large"; addressing = "ia";
    packageToBuild = largePackageToBuild;
    isLarge = true; isMemoryConstrained = false;
  };
  smallCaSign = smallCaSet."small-ca-sign";
  sigstore = import ./small-sigstore.nix { inherit pkgs system laut laut-sign-only; };
  caIdentityProbe = laut-sign-only.overrideAttrs (old: {
    pname = "laut-ca-identity-probe";
    cargoBuildFlags = [ "--no-default-features" "--package" "laut-sign" "--example" "ca_identity_probe" ];
    installPhase = ''
      runHook preInstall
      install -Dm755 target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/examples/ca_identity_probe $out/bin/ca_identity_probe
      runHook postInstall
    '';
  });
  experimentTestSource = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./experiment.py
      ./seed-inputs.py
      ./compare-experiments.py
      ./experiment_bundles.py
      ./test_experiment.py
      ./test_seed_inputs.py
      ./test_compare_experiments.py
      ./test_experiment_bundles.py
      ./ca-oracle.py
      ./test_ca_oracle.py
    ];
  };
in
  smallCaSet // smallIaSet // mediumCaSet // mediumIaSet // largeCaSet // largeIaSet // equivalenceSigns // {
    small-equivalence-outputs = pkgs.runCommand "laut-small-equivalence-outputs" {
      nativeBuildInputs = [ pkgs.python3 pkgs.difftastic ];
    } ''
      python3 -B - <<'PY'
      import importlib.util
      import json
      import os
      from pathlib import Path
      import sys

      sys.path.insert(0, "${experimentTestSource}")
      spec = importlib.util.spec_from_file_location(
          "compare_experiments", "${experimentTestSource}/compare-experiments.py"
      )
      comparator = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(comparator)
      ia = Path("${equivalenceSigns.small-equivalence-ia-sign}")
      ca = Path("${equivalenceSigns.small-equivalence-ca-sign}")
      rebuilt = {
          "bootstrap-tools",
          "bootstrap-stage0-stdenv-linux",
          "bootstrap-stage0-glibc-bootstrapFiles",
          "bootstrap-stage0-binutils-wrapper-",
      }
      boundaries = {"busybox", "bootstrap-tools.tar.xz"}
      reports = {}
      for builder in ("builderA", "builderB"):
          # The comparator's exit code also rejects input/recipe differences.
          # Keep those differences and blocked attribution, but gate outputs only.
          report, _ = comparator.compare(
              ia / "experiment" / builder / "laut-experiment",
              ca / "experiment" / builder / "laut-experiment",
              ia / "cache", ca / "cache",
          )
          destination = Path(os.environ["out"]) / builder
          destination.mkdir(parents=True)
          comparator.write_preimages(report, destination)
          (destination / "report.json").write_text(
              json.dumps(report, indent=2, sort_keys=True) + "\n"
          )
          reports[builder] = report
          print(f"{builder}: comparator status={report['status']}; "
                f"counts={report.get('counts', {})}", flush=True)

      for builder, report in reports.items():
          assert report["version"] == 1, builder
          assert report["status"] in {"failed", "diagnostic-agreement"}, builder
          assert "unsupported" not in report, builder
          assert not report.get("invalid_reason"), builder
          assert not report.get("configuration_differences"), builder
          assert report["scope"] == "ia-ca", builder
          assert report["signed_claims"] == "diagnostic", builder
          assert not report["errors"], (builder, report["errors"])
          assert not report["correspondence"], builder
          assert report["unpaired"] == {"left": [], "right": []}, builder
          nodes = {node["name"]: node for node in report["nodes"]}
          assert len(report["nodes"]) == 6, builder
          assert nodes.keys() == rebuilt | boundaries, (builder, nodes.keys())
          for name, node in nodes.items():
              context = (builder, name)
              assert node["correspondence"] == "rooted-unique", context
              assert node["status"] in {"evidence-agrees", "divergent", "blocked"}, context
              assert not node.get("source_errors"), context
              for output in node["outputs"].values():
                  assert all("error" not in output[side] for side in ("left", "right")), context
              if name in boundaries:
                  assert node["synthetic_identity"] == "excluded-fixed-output-boundary", context
                  assert node["normalized_inputs"] == "excluded-fixed-output-boundary", context
                  continue
              requested = set(node["requested_outputs"])
              assert requested, context
              assert node["normalized_inputs"] in {"equal", "divergent"}, context
              assert node["signed_evidence"].keys() == {"left", "right"}, context
              for evidence in node["signed_evidence"].values():
                  assert "error" not in evidence, (context, evidence)
                  assert evidence["outputs"].keys() == requested, context
                  assert evidence["resolved_input"] and evidence["aterm"], context
              assert node["signed_outputs"].keys() == requested, context
              assert all(output["status"] == "equal" and not output["differences"]
                         for output in node["signed_outputs"].values()), context
              assert node["synthetic_identity"] == "equal", context
          print(f"{builder}: all four rebuilt nodes' signed output identities agree. "
                "Full equivalence and signature authentication are NOT established.")
      PY
    '';
    experiment-tools = pkgs.runCommand "laut-experiment-tools-tests" {
      nativeBuildInputs = [ pkgs.python3 pkgs.python3Packages.flake8 ];
    } ''
      flake8 ${experimentTestSource}/experiment.py ${experimentTestSource}/seed-inputs.py ${experimentTestSource}/compare-experiments.py ${experimentTestSource}/experiment_bundles.py ${experimentTestSource}/ca-oracle.py
      python3 -B -m unittest discover -s ${experimentTestSource} -p 'test_*.py' -v
      touch "$out"
    '';
    small-sigstore-sign = sigstore.sign;
    small-ca-oracle = import ./small-ca-oracle.nix {
      inherit pkgs system;
      nixPackage = nixSeededPackage;
      nixRevision = nix-seeded.rev;
      patches = nixSeededPatches;
      probe = caIdentityProbe;
    };
    small-sigstore-verify = sigstore.verify;
    # Exercises the hash-divergence debug probe end-to-end: reuses the
    # small-ca-sign cache (preimages on), tampers one trace's preimage with a
    # known marker on the verifier, then runs `laut verify
    # --debug-preimage-corpus file://...` and asserts difft surfaces the
    # marker. CA-only for now; an IA analog can come later alongside other
    # out-of-scope IA followups.
    #
    # The verifierExtraConfig injects just-this-test-needs-it tooling:
    # difftastic for the structural diff, and a writePython3Bin-wrapped
    # tamper helper that becomes a PATH-accessible `tamper-preimage` command.
    debug-probe = import ./test-template.nix (fullArgs // {
      testName = "debug-probe";
      testScriptFile = ./debug-probe-script.py;
      binaryCacheData = "${smallCaSign}/cache";
      packageToBuild = smallPackageToBuild;
      addressing = "ca";
      isMemoryConstrained = false;
      needsExtraTime = false;
      verifierExtraConfig = {
        environment.systemPackages = [
          pkgs.difftastic
          (pkgs.writers.writePython3Bin "tamper-preimage" { } (
            builtins.readFile ./tamper-preimage.py
          ))
        ];
      };
    });
  }

  # Full local reproducibility model - trusts only itself
  #fullReproVM = import ./test-template.nix (fullArgs // {
  #  testName = "fullReproVM";
    # verifierExtraConfig.nix = {
    #   extraOptions = "experimental-features = nix-command flakes";
    #   settings = {
    #       substituters = [ ];
    #       trusted-public-keys = [ ];
    #   };
    # };
    #  trust_model = Builder(self())
#    });

  # Trusted infrastructure model - trusts central cache
  #trustedInfraVM = import ./test-template.nix (fullArgs // {
  #  testName = "trustedInfraVM";
  #  verifierExtraConfig = {
  #    nix = {
  #    extraOptions = "experimental-features = nix-command flakes";
  #    settings = {
  #      substituters = [ "http://cache.local" ];
  #      trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
  #    };
  #    };
      #  trust_model = threshold(1,
      #   Builder(self()),
      #   Signer("cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=", legacy=true))
 #   };});


  # Distributed trust model - requires multiple builder agreement
 # distributedTrustVM = import ./test-template.nix (fullArgs // {
 #   testName = "distributedTrustVM";
 #   verifierExtraConfig.nix = {
 #     extraOptions = "experimental-features = nix-command flakes";
 #     settings = {
 #       substituters = [
 #         "http://builder1.local"
 #         "http://builder2.local"
 #       ];
 #       trusted-public-keys = [
 #         "builder1.local:${placeholder "BUILDER1_KEY"}"
 #         "builder2.local:${placeholder "BUILDER2_KEY"}"
 #       ];
 #     };
      #  trust_model = threshold(2,
      #   Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU="),
      #   Builder("builderB:iN9OEB6nRfDK0Ae8fscfOZAjWPXn4CdIIHiaMwWxXQk="))
 #   };});

  #attestBuilder = import ./test-template.nix (fullArgs // {
  #  testName = "attestBuilder";
  #  verifierExtraConfig.nix = {
  #      extraOptions = "experimental-features = nix-command flakes";
  #      substituters = [ "http://cache.local" ];
  #      trusted-public-keys = [ "cache.local:${placeholder "CACHE_KEY"}" ];
  #    };
    #  trust_model = Builder("builderA:IRs7KiYMNnwMOui+D4VufEelbplIR7vzbMIDJjaG5GU=",
    #     sw_flake = "github:nixos/nixpkgs-builders/8d99dd5e331e9fc8f3480d739b709eafc1e4ceb6#amd-tpm-2.0",
    #     host_sw_criteria = SW_CRITERIA.TPM-2.0_STRICT,
    #     host_hw_criteria = HW_CRTIERIA.HP_MILAN_NO_PUBLIC_VULN,
    #     host_identity = "smRvhWX9+vVTe3gpNsAp4EuJmUtdw2Ih9xcp+Mjd+6g=",
    #     host_sw_exclude = SW_CRITERIA.DRVS_WITH_VULNS + nixpkgsRange("xyutils", "5.6.0", "5.6.1"))
  #});
