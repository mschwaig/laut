"""Run: python3 -m unittest discover -s vm-tests -p test_experiment.py -v"""

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import experiment


def path(name):
    return "/nix/store/" + "0" * 32 + "-" + name


ROOT = path("root.drv")
DEP = path("tool.drv")
RESOLVED = path("resolved-root.drv")
OUT = path("root")
TOOL = path("tool")
UNUSED = path("unused")
SOURCE = path("source")
REFERENCE = path("reference")


def drv(outputs, sources=(), dependencies=None):
    return {"version": 4, "name": "same-name-is-not-identity",
            "outputs": outputs, "inputs": {
                "srcs": [Path(p).name for p in sources],
                "drvs": {Path(p).name: {"outputs": names, "dynamicOutputs": {}}
                         for p, names in (dependencies or {}).items()}}}


def aterm(outputs):
    tuples = [
        "(" + ",".join(json.dumps(s) for s in (name, p or "", "", "")) + ")"
        for name, p in outputs.items()]
    text = "Derive([" + ",".join(tuples) + '],[],[],"system","builder",[],[])'
    return text.encode()


def metadata(references=()):
    return {"version": 2, "storeDir": "/nix/store", "narSize": 42,
            "narHash": {"algorithm": "sha256", "hash": "actual-nix-value"},
            "references": [Path(p).name for p in references],
            "unseeded": {"path": Path(path("unseeded")).name,
                         "narHash": "verbatim-experimental-data"}}


class FakeNix:
    def __init__(self):
        self.drvs = {
            ROOT: drv({"out": {"path": Path(OUT).name}},
                      [SOURCE], {DEP: ["out"]}),
            DEP: drv({"out": {"hash": "sha256-real", "method": "flat"},
                      "dev": {"path": Path(UNUSED).name}}),
        }
        self.aterms = {ROOT: aterm({"out": OUT}),
                       DEP: aterm({"out": TOOL, "dev": UNUSED})}
        self.valid = {SOURCE: metadata(), TOOL: metadata(),
                      REFERENCE: metadata()}
        self.resolutions = {}
        self.calls = []
        self.failures = {}

    def __call__(self, command, capture_output, check):
        assert capture_output and not check
        assert command[:3] == ["nix", "--store", "local"]
        args = command[3:]
        self.calls.append(args)
        if tuple(args) in self.failures:
            code, stdout = self.failures[tuple(args)]
            return subprocess.CompletedProcess(
                command, code, stdout, b"Nix failure")
        if args[:2] == ["derivation", "show"]:
            selected = self.drvs if "--recursive" in args else {
                args[-1]: self.drvs[args[-1]]}
            output = json.dumps({"version": 4, "derivations": {
                Path(p).name: d for p, d in selected.items()}}).encode()
        elif args[:2] == ["store", "cat"]:
            output = self.aterms[args[2]]
        elif args[0] == "path-info":
            assert "--json-format" in args and args[args.index(
                "--json-format") + 1] == "2"
            if "--all" in args:
                selected = self.valid
            else:
                requested = args[args.index("2") + 1:]
                selected = {}
                for p in requested:
                    if "^" in p:
                        if p not in self.resolutions:
                            return subprocess.CompletedProcess(
                                command, 1, b"", b"unresolved")
                        p = self.resolutions[p]
                    selected[p] = self.valid.get(p)
            output = json.dumps({
                "version": 2, "storeDir": "/nix/store", "info": {
                    Path(p).name: info for p, info in selected.items()}}
            ).encode()
        elif args[0] == "copy":
            assert args[1] == "--no-check-sigs"
            assert args[2] == "--to" and args[3].startswith("file://")
            assert args[3].endswith("/builderA/contents")
            assert set(args[4:]) <= self.valid.keys()
            output = b""
        else:
            raise AssertionError(f"unexpected Nix command: {args}")
        return subprocess.CompletedProcess(command, 0, output, b"")


class ExperimentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.state = self.base / "state"
        self.manifest = self.base / "manifest.json"
        self.config = {"id": "test", "addressing": "ia", "seed": "seed-a",
                       "target": "hello", "system": "x86_64-linux",
                       "nixPackage": path("nix"), "nixRevision": "revision",
                       "nixpkgs": {
                           "source": path("nixpkgs"), "revision": "rev"},
                       "laut-sign-only": path("laut-sign-only")}
        self.manifest.write_text(json.dumps(self.config))
        self.public_key = self.base / "public-key"
        self.public_key.write_text(
            "builder:" + base64.b64encode(b"p" * 32).decode())
        self.nix = FakeNix()
        for patcher in (
                patch.object(experiment.subprocess, "run", self.nix),
                patch.object(experiment.socket, "gethostname",
                             return_value="builderA")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def cli(self, *args, env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            with contextlib.redirect_stderr(io.StringIO()):
                return experiment.main(["--state", str(self.state), *args])

    def begin(self):
        return self.cli("begin", ROOT, "--manifest", str(self.manifest),
                        "--public-key", str(self.public_key))

    def record(self, status=0, drv_path=ROOT, outputs=OUT, extra=()):
        return self.cli("record", "--sign-status", str(status), *extra,
                        env={"DRV_PATH": drv_path, "OUT_PATHS": outputs})

    def read(self, name):
        return json.loads((self.state / name).read_bytes())

    def observations(self):
        return sorted((self.state / "observations").iterdir())

    def test_begin_preserves_v4_exact_aterms_actual_fod_paths_and_public_key(
            self):
        self.assertEqual(self.begin(), 0)
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["hostname"], "builderA")
        self.assertEqual(manifest["root_drv"], ROOT)
        self.assertEqual(manifest["public_key"], self.public_key.read_text())
        for key, value in self.config.items():
            self.assertEqual(manifest[key], value)
        self.assertEqual(self.read("derivations.json")["version"], 4)
        self.assertEqual(self.read("inventory.json")[
                         DEP]["outputs"]["out"], TOOL)
        self.assertEqual(self.read("inventory.json")[
                         ROOT]["input_sources"], [SOURCE])
        self.assertEqual(self.read("inventory.json")[
                         ROOT]["input_derivations"], {DEP: ["out"]})
        self.assertEqual((self.state / "aterms" / Path(DEP).name).read_bytes(),
                         self.nix.aterms[DEP])
        self.assertEqual(
            set(self.read("prebuild-valid-paths.json")), set(self.nix.valid))
        self.assertNotIn(OUT, self.read("prebuild-valid-paths.json"))

    def test_repeated_hooks_keep_distinct_snapshots_and_only_exit_status(self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.record(0), 0)
        self.nix.valid[OUT] = metadata([REFERENCE])
        self.assertEqual(self.record(
            117, extra=("--optional-failure", "upload exited 1")), 0)
        self.assertEqual(self.record(1), 0)
        observations = self.observations()
        self.assertEqual(len(observations), 3)
        reports = [json.loads((d / "status.json").read_bytes())
                   for d in observations]
        self.assertEqual({r["sign_exit_status"] for r in reports}, {0, 117, 1})
        for report, directory in zip(reports, observations):
            self.assertEqual(report["status"], "complete")
            self.assertNotIn("signed", report)
            self.assertNotIn("verified", report)
            self.assertEqual(
                (directory / "derivation.aterm").read_bytes(),
                self.nix.aterms[ROOT])
            snapshot = json.loads(
                (directory / "output-path-info.json").read_bytes())
            info = snapshot["info"][Path(OUT).name]
            self.assertEqual(info["unseeded"], metadata()["unseeded"])
            references = ([] if report["sign_exit_status"] == 0
                          else [Path(REFERENCE).name])
            self.assertEqual(info["references"], references)
            if report["sign_exit_status"] == 117:
                self.assertFalse(report["errors"][0]["required"])

    def test_collect_includes_buildtime_only_inputs_and_registered_refs(self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid[OUT] = metadata([REFERENCE])
        self.assertEqual(self.record(), 0)
        self.assertEqual(self.cli("collect"), 0)
        paths = self.read("paths.json")
        self.assertTrue(paths[TOOL]["prebuild_valid"])
        self.assertEqual(paths[TOOL]["hook_invocations"], [])
        self.assertFalse(paths[OUT]["prebuild_valid"])
        self.assertEqual(len(paths[OUT]["hook_invocations"]), 1)
        self.assertIn("build-input-output", paths[TOOL]["roles"])
        self.assertIn("registered-reference", paths[REFERENCE]["roles"])
        self.assertEqual(paths[UNUSED]["collection_status"], "missing")
        self.assertFalse(paths[UNUSED]["required"])
        exported = {p for call in self.nix.calls
                    if call[0] == "copy" for p in call[4:]}
        self.assertEqual(exported, {OUT, TOOL, SOURCE, REFERENCE})
        report = self.read("collect.json")
        self.assertEqual(report["root_outputs"], [OUT])
        self.assertEqual(report["status"], "complete")
        self.assertNotIn("equivalent", report)

    def test_preexisting_outputs_without_hooks_are_not_observed_built(self):
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.begin(), 0)
        self.assertEqual(self.cli("collect"), 0)
        item = self.read("paths.json")[OUT]
        self.assertTrue(item["prebuild_valid"])
        self.assertEqual(item["hook_invocations"], [])

    def test_newly_valid_output_without_hook_is_classified_as_missing_evidence(
            self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.cli("collect"), 1)
        item = self.read("paths.json")[OUT]
        self.assertFalse(item["prebuild_valid"])
        self.assertEqual(item["collection_status"], "valid")
        self.assertEqual(item["hook_invocations"], [])
        self.assertTrue(any("no hook observation" in e["error"]
                            for e in self.read("collect.json")["errors"]))

    def test_multiple_outputs_snapshot_is_exact_and_not_inferred_from_drv(
            self):
        self.nix.drvs[ROOT]["outputs"]["dev"] = {"path": Path(UNUSED).name}
        self.nix.aterms[ROOT] = aterm({"out": OUT, "dev": UNUSED})
        self.assertEqual(self.begin(), 0)
        self.nix.valid.update({OUT: metadata(), UNUSED: metadata()})
        self.assertEqual(self.record(outputs=f"{OUT}  {UNUSED}\n"), 0)
        snapshot = experiment.path_info(
            (self.observations()[0] / "output-path-info.json").read_bytes())
        self.assertEqual(set(snapshot), {OUT, UNUSED})
        self.assertEqual(self.cli("collect"), 0)
        self.assertEqual(set(self.read("collect.json")[
                         "root_outputs"]), {OUT, UNUSED})

    def test_deleted_required_raw_artifacts_make_collection_incomplete(self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.record(), 0)
        (self.state / "aterms" / Path(ROOT).name).unlink()
        (self.observations()[0] / "derivation.aterm").unlink()
        self.assertEqual(self.cli("collect"), 1)
        errors = self.read("collect.json")["errors"]
        self.assertTrue(
            any(e["artifact"] == f"original:{ROOT}" for e in errors))
        self.assertTrue(any(e["artifact"].startswith(
            "observation:") for e in errors))

    def ca_root(self):
        self.nix.drvs[ROOT]["outputs"] = {
            "out": {"hashAlgo": "sha256", "method": "nar"}}
        self.nix.aterms[ROOT] = aterm({"out": None})
        self.assertEqual(self.begin(), 0)
        self.nix.drvs[RESOLVED] = drv(
            {"out": {"hashAlgo": "sha256", "method": "nar"}}, [TOOL, SOURCE])
        self.nix.aterms[RESOLVED] = aterm({"out": None})
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.record(drv_path=RESOLVED), 0)

    def test_ca_root_uses_registered_realization_not_resolved_drv_name(self):
        self.ca_root()
        self.nix.resolutions[ROOT + "^out"] = OUT
        self.assertEqual(self.cli("collect"), 0)
        self.assertEqual(self.read("collect.json")["root_outputs"], [OUT])
        self.assertIn(OUT, self.read("paths.json"))
        self.assertNotIn(RESOLVED, self.read("inventory.json"))

    def test_unresolved_ca_root_is_incomplete_despite_successful_hook(self):
        self.ca_root()
        self.assertEqual(self.cli("collect"), 1)
        report = self.read("collect.json")
        self.assertEqual(report["root_outputs"], [])
        self.assertEqual(report["unresolved_outputs"], [ROOT + "^out"])
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("hook-output", self.read("paths.json")[OUT]["roles"])
        self.assertNotIn("root-output", self.read("paths.json")[OUT]["roles"])

    def test_required_source_missing_is_not_optional_unused_output(self):
        self.assertEqual(self.begin(), 0)
        del self.nix.valid[SOURCE]
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.cli("collect"), 1)
        paths = self.read("paths.json")
        self.assertTrue(paths[SOURCE]["required"])
        self.assertFalse(paths[UNUSED]["required"])
        self.assertEqual(paths[SOURCE]["collection_status"], "missing")
        self.assertTrue(any(e["artifact"] == SOURCE and e["required"]
                            for e in self.read("collect.json")["errors"]))

    def test_missing_reference_and_copy_failure_fail_collection(self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid[OUT] = metadata([UNUSED])
        self.assertEqual(self.cli("collect"), 1)
        self.assertTrue(self.read("paths.json")[UNUSED]["required"])
        self.nix.valid[UNUSED] = metadata()
        copied = sorted(self.nix.valid)
        destination = (self.state / "builderA" / "contents").as_uri()
        command = ("copy", "--no-check-sigs", "--to", destination, *copied)
        # REFERENCE is no longer relevant to this graph.
        command = tuple(value for value in command if value != REFERENCE)
        self.nix.failures[command] = (1, b"partial copy")
        self.assertEqual(self.cli("collect"), 1)
        self.assertEqual(
            self.read("copy-0.stdout.status.json")["status"],
            "error")
        self.assertEqual(
            (self.state / "copy-0.stdout").read_bytes(),
            b"partial copy")

    def test_record_failure_still_captures_other_snapshots_and_blocks_collect(
            self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid[OUT] = metadata()
        self.nix.failures[("derivation", "show", ROOT)] = (1, b"partial JSON")
        self.assertEqual(self.record(), 1)
        directory = self.observations()[0]
        self.assertEqual(
            (directory / "derivation.json").read_bytes(),
            b"partial JSON")
        self.assertTrue((directory / "derivation.aterm").exists())
        self.assertTrue((directory / "output-path-info.json").exists())
        self.assertEqual(self.cli("collect"), 1)
        self.assertTrue(any(e["artifact"].startswith("observation:")
                            for e in self.read("collect.json")["errors"]))

    def test_missing_output_snapshot_fails_even_with_successful_sign_status(
            self):
        self.assertEqual(self.begin(), 0)
        self.assertEqual(self.record(), 1)
        report = json.loads(
            (self.observations()[0] /
             "status.json").read_bytes())
        self.assertEqual(report["sign_exit_status"], 0)
        self.assertEqual(report["status"], "incomplete")

    def test_empty_collection_cannot_succeed(self):
        self.assertEqual(self.begin(), 0)
        self.nix.valid.clear()
        self.assertEqual(self.cli("collect"), 1)
        self.assertEqual(self.read("collect.json")["realized_path_count"], 0)
        self.assertFalse(any(call[0] == "copy" for call in self.nix.calls))

    def test_private_key_is_rejected_without_export(self):
        self.public_key.write_text(
            "builder:" + base64.b64encode(b"secret!!" * 8).decode())
        self.assertEqual(self.begin(), 1)
        self.assertFalse((self.state / "manifest.json").exists())
        self.assertNotIn("c2VjcmV0", (self.state / "begin.json").read_text())
        self.assertEqual(self.nix.calls, [])

    def test_old_json_bad_paths_and_dynamic_inputs_are_rejected(self):
        for raw in ({ROOT: {}}, {"version": 3, "derivations": {ROOT: {}}},
                    {"version": 4, "derivations": {ROOT: self.nix.drvs[ROOT]}},
                    {"version": 4, "derivations": {}}):
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError, KeyError)):
                    experiment.derivations(json.dumps(raw))
        for p in ("/etc/nix/private-key",
                  "/nix/store/../secret", "not-a-path"):
            with self.subTest(path=p), self.assertRaises(ValueError):
                experiment.store_path(p)
        node = self.nix.drvs[ROOT]["inputs"]["drvs"][Path(DEP).name]
        node["dynamicOutputs"] = {"out": {}}
        self.assertEqual(self.begin(), 1)

    def test_missing_hook_environment_and_interrupted_observation_are_errors(
            self):
        self.assertEqual(self.begin(), 0)
        self.assertEqual(self.cli("record", "--sign-status", "0"), 1)
        self.nix.valid[OUT] = metadata()
        self.assertEqual(self.record(), 0)
        for directory in self.observations():
            (directory / "status.json").unlink()
        self.assertEqual(self.cli("collect"), 1)

    def test_begin_cannot_overwrite_original_snapshot(self):
        self.assertEqual(self.begin(), 0)
        original = (self.state / "prebuild-valid-paths.json").read_bytes()
        self.nix.valid[OUT] = metadata()
        with self.assertRaises(SystemExit):
            self.begin()
        self.assertEqual(
            (self.state / "prebuild-valid-paths.json").read_bytes(),
            original)


if __name__ == "__main__":
    unittest.main()
