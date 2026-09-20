"""Run: python3 -m unittest discover -s vm-tests -p test_seed_inputs.py -v

All Nix subprocesses are mocked; these tests never access the host store.
"""

import base64
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "seed_inputs", Path(__file__).with_name("seed-inputs.py"))
seed_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed_inputs)


def store_path(digit="0", name="source-with-hyphens.tar.gz"):
    return f"/nix/store/{digit * 32}-{name}"


def sri(algorithm="sha256", size=32):
    return algorithm + "-" + base64.b64encode(bytes(size)).decode()


def metadata(mode="flat", algorithm="sha256", size=32):
    return {"version": 2, "storeDir": "/nix/store", "references": [],
            "ca": {"method": mode, "hash": sri(algorithm, size)},
            "narHash": sri(), "narSize": 120}


class SeedInputsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.sources = Path(temporary.name) / "sources.json"
        self.output = Path(temporary.name) / "state" / "mapping.json"
        self.original = store_path()
        self.canonical = self.original
        self.expected = store_path("1")
        self.actual = self.expected
        self.seed = "experiment-seed"
        self.before = metadata()
        self.after = copy.deepcopy(self.before)
        self.descriptor = {"path": self.original, "ca": copy.deepcopy(self.before["ca"])}
        self.before["ca"] = None
        self.write_sources()
        mock = patch.object(seed_inputs.subprocess, "run", side_effect=self.run_nix)
        self.run = mock.start()
        self.addCleanup(mock.stop)

    def run_nix(self, command, *, check, capture_output, text):
        self.assertTrue(check and capture_output and text)
        self.assertEqual(command[:3], ["nix", "--store", "local"])
        args = command[3:]
        canonical = args[:2] == ["--store-path-seed", ""]
        if canonical:
            args = args[2:]
            self.assertIn("--dry-run", args)
        if args == ["config", "show", "store-path-seed"]:
            result = self.seed
        elif args[:4] == ["path-info", "--json", "--json-format", "2"]:
            self.assertEqual(len(args), 5)
            path = args[4]
            self.assertIn(path, (self.original, self.actual))
            info = self.before if path == self.original else self.after
            result = json.dumps({"version": 2, "storeDir": "/nix/store",
                                 "info": {Path(path).name: info}})
        elif args[:2] == ["store", "add"]:
            ca = self.descriptor["ca"]
            expected_args = ["store", "add", "--mode", ca["method"],
                             "--hash-algo", ca["hash"].split("-", 1)[0],
                             "--name", Path(self.original).name[33:]]
            if "--dry-run" in args:
                expected_args.append("--dry-run")
            expected_args.append(self.original)
            self.assertEqual(args, expected_args)
            result = self.canonical if canonical else (
                self.expected if "--dry-run" in args else self.actual)
        else:
            self.fail(f"unexpected Nix command: {command}")
        return subprocess.CompletedProcess(command, 0, result + "\n", "")

    def invoke(self, seed=None):
        seed_inputs.seed_inputs(self.sources, self.output, seed)

    def write_sources(self, descriptors=None):
        self.sources.write_text(json.dumps(
            [self.descriptor] if descriptors is None else descriptors))

    def assert_no_add(self):
        self.assertFalse(any(call.args[0][3:5] == ["store", "add"]
                             for call in self.run.call_args_list))
        self.assertFalse(self.output.exists())

    def test_modes_algorithms_and_exact_name(self):
        for mode in ("flat", "nar"):
            for algorithm, size in (("sha1", 20), ("sha256", 32), ("sha512", 64)):
                with self.subTest(mode=mode, algorithm=algorithm):
                    self.run.reset_mock()
                    self.before = metadata(mode, algorithm, size)
                    self.after = copy.deepcopy(self.before)
                    self.descriptor["ca"] = copy.deepcopy(self.before["ca"])
                    self.before["ca"] = None
                    self.write_sources()
                    self.invoke(self.seed)
                    self.assertEqual(json.loads(self.output.read_text()), {
                        self.original: {"seeded": self.actual, **{
                            key: self.after[key] for key in ("ca", "narHash", "narSize")}}})
                    commands = [call.args[0][3:] for call in self.run.call_args_list]
                    self.assertEqual(len(commands), 6)
                    self.assertEqual(commands[2][:2], ["--store-path-seed", ""])
                    self.assertIn("--dry-run", commands[2])
                    self.assertIn("--dry-run", commands[3])
                    self.assertNotIn("--store-path-seed", commands[3])
                    self.assertNotIn("--dry-run", commands[4])
                    self.assertNotIn("--store-path-seed", commands[4])
                    self.assertEqual(commands[5][-1], self.actual)

    def test_rejects_references_including_self(self):
        for references in ([Path(store_path("2")).name], [Path(self.original).name], None):
            with self.subTest(references=references):
                self.before["references"] = references
                with self.assertRaisesRegex(ValueError, "references"):
                    self.invoke()
                self.assert_no_add()

    def test_rejects_missing_or_non_fixed_content_address(self):
        for ca in (None, "fixed:sha256:legacy", {"method": "text"}, {"method": "git"}):
            with self.subTest(ca=ca):
                self.descriptor["ca"] = ca
                self.write_sources()
                with self.assertRaisesRegex(ValueError, "fixed flat/nar"):
                    self.invoke()
                self.assert_no_add()

    def test_rejects_invalid_declared_hash(self):
        for hash_value in (None, {"algorithm": "sha256"}, "sha256-", "not-SRI!"):
            with self.subTest(hash=hash_value):
                self.descriptor["ca"]["hash"] = hash_value
                self.write_sources()
                with self.assertRaisesRegex(ValueError, "SRI content hash"):
                    self.invoke()
                self.run.assert_not_called()

    def test_rejects_invalid_nar_metadata(self):
        for change in ({"narHash": None}, {"narSize": -1}, {"narSize": True}):
            with self.subTest(change=change):
                self.before = {**metadata(), **change}
                with self.assertRaises(ValueError):
                    self.invoke()
                self.assert_no_add()

    def test_rejects_wrong_path_info_envelope(self):
        for data in ([], {self.original: self.before},
                     {"version": 2, "storeDir": "/other/store", "info": {}},
                     {"version": 2, "storeDir": "/nix/store", "info": {
                         Path(self.expected).name: self.before}}):
            with self.subTest(data=data):
                self.run.side_effect = [
                    subprocess.CompletedProcess([], 0, self.seed + "\n", ""),
                    subprocess.CompletedProcess([], 0, json.dumps(data), ""),
                ]
                with self.assertRaisesRegex(ValueError, "format-2 envelope"):
                    self.invoke()
                self.assert_no_add()

    def test_all_inputs_validated_before_add(self):
        self.write_sources([self.descriptor, {**self.descriptor, "path": self.actual}])
        self.after["references"] = [Path(self.original).name]
        with self.assertRaisesRegex(ValueError, "references"):
            self.invoke()
        self.assert_no_add()

    def test_rejects_dry_run_name_change(self):
        self.expected = store_path("1", "wrong-name")
        with self.assertRaisesRegex(ValueError, "invalid dry-run store path"):
            self.invoke()
        self.assertEqual(self.run.call_count, 4)
        self.assertFalse(self.output.exists())

    def test_rejects_returned_path_mismatch(self):
        self.actual = store_path("2")
        with self.assertRaisesRegex(ValueError, "added path.*!= dry-run"):
            self.invoke()
        self.assertFalse(self.output.exists())

    def test_rejects_canonical_path_mismatch_before_add(self):
        self.canonical = store_path("2")
        with self.assertRaisesRegex(ValueError, "canonical dry-run path.*!= original"):
            self.invoke()
        self.assertEqual(self.run.call_count, 3)
        self.assertEqual(self.run.call_args.args[0][3:5], ["--store-path-seed", ""])
        self.assertIn("--dry-run", self.run.call_args.args[0])
        self.assertFalse(self.output.exists())

    def test_registered_ca_is_not_used(self):
        for registered in (None, {"method": "nar", "hash": sri("sha512", 64)}):
            with self.subTest(registered=registered):
                self.before["ca"] = self.after["ca"] = registered
                self.invoke()
                entry = json.loads(self.output.read_text())[self.original]
                self.assertEqual(entry["ca"], self.descriptor["ca"])
                self.assertEqual(entry["narHash"], self.after["narHash"])
                self.assertEqual(entry["narSize"], self.after["narSize"])

    def test_rejects_changed_nar_metadata_or_added_references(self):
        for change in ({"narHash": sri("sha512", 64)}, {"narSize": 999},
                       {"references": [Path(self.original).name]}):
            with self.subTest(change=change):
                self.after = {**metadata(), **change}
                with self.assertRaises(ValueError):
                    self.invoke()
                self.assertFalse(self.output.exists())

    def test_empty_seed_identity_explicit_and_queried(self):
        self.seed = ""
        self.expected = self.actual = self.original
        for seed in ("", None):
            with self.subTest(seed=seed):
                self.invoke(seed)
                self.assertEqual(json.loads(self.output.read_text())[
                    self.original]["seeded"], self.original)
                self.assertEqual(json.loads(self.output.read_text())[
                    self.original]["ca"], self.descriptor["ca"])

    def test_empty_seed_nonidentity_rejected_before_add(self):
        self.seed = ""
        with self.assertRaisesRegex(ValueError, "empty seed must preserve path identity"):
            self.invoke("")
        self.assertEqual(self.run.call_count, 4)
        self.assertIn("--dry-run", self.run.call_args.args[0])
        self.assertFalse(self.output.exists())

    def test_seed_mismatch_is_not_an_override(self):
        with self.assertRaisesRegex(ValueError, "configured seed"):
            self.invoke("")
        self.assert_no_add()

    def test_duplicate_inputs_are_only_added_once(self):
        self.write_sources([self.descriptor, self.descriptor])
        self.invoke()
        self.assertEqual(self.run.call_count, 6)

    def test_conflicting_declarations_rejected(self):
        self.write_sources([self.descriptor, {"path": self.original,
                                            "ca": metadata("nar")["ca"]}])
        with self.assertRaisesRegex(ValueError, "conflicting content address"):
            self.invoke()
        self.run.assert_not_called()

    def test_empty_manifest(self):
        self.sources.write_text("[]")
        self.invoke()
        self.assertEqual(json.loads(self.output.read_text()), {})
        self.assertEqual(self.run.call_count, 1)

    def test_invalid_manifest(self):
        for manifest in ({}, [1], [self.original], [{}], [{"path": 42}],
                         [{"path": "relative"}], [{"path": "/nix/store/not-a-store-path"}]):
            with self.subTest(manifest=manifest):
                self.sources.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "descriptor"):
                    self.invoke()
                self.run.assert_not_called()

    def test_nix_failure_reports_error_without_output(self):
        self.run.side_effect = subprocess.CalledProcessError(
            1, ["nix"], stderr="mock Nix failure\n")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = seed_inputs.main(["--sources", str(self.sources),
                                       "--output", str(self.output), "--seed", self.seed])
        self.assertEqual(status, 1)
        self.assertIn("laut-seed-inputs: mock Nix failure", stderr.getvalue())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
