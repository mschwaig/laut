"""Run: python3 -m unittest discover -s vm-tests \
    -p test_compare_experiments.py -v
"""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from experiment_bundles import BUILD_TYPES
from test_experiment_bundles import ATERM, BUILDER, HASH, HINT, PUBLIC_KEY, encode


spec = importlib.util.spec_from_file_location(
    "compare_experiments", Path(__file__).with_name("compare-experiments.py")
)
comparator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparator)


def path(name, digit="0"):
    return "/nix/store/" + digit * 32 + "-" + name


def fixture(seed="", addressing="ia", digit="0", graph=None, names=None):
    graph = graph or {"root": ["tool"], "tool": []}
    names = names or {}
    manifest = {
        "schema_version": 1,
        "run_id": str(uuid.uuid4()),
        "id": "trial",
        "addressing": addressing,
        "seed": seed,
        "target": "root",
        "system": "x86_64-linux",
        "nixPackage": path("nix"),
        "nixRevision": "nix-revision",
        "laut-sign-only": path("laut"),
        "nixpkgs": {"source": path("nixpkgs"), "revision": "nixpkgs-revision"},
        "root_drv": path("root.drv", digit),
    }
    data = {
        "manifest": manifest,
        "begin": {"status": "complete", "errors": []},
        "derivations": {"version": 4, "derivations": {}},
        "inventory": {},
        "collect": {
            "status": "complete",
            "errors": [],
            "output_paths": {},
            "unresolved_outputs": [],
            "root_outputs": [path("root", digit)],
        },
        "realized-path-info": {},
        "paths": {},
    }
    for name, deps in graph.items():
        drv, out = path(name + ".drv", digit), path(name, digit)
        dependencies = {path(d + ".drv", digit): ["out"] for d in deps}
        outputs = (
            {"out": {"path": Path(out).name}}
            if addressing == "ia"
            else {"out": {"method": "nar", "hashAlgo": "sha256"}}
        )
        data["derivations"]["derivations"][Path(drv).name] = {
            "version": 4,
            "name": names.get(name, name),
            "outputs": outputs,
            "inputs": {
                "srcs": [],
                "drvs": {
                    Path(p).name: {"outputs": ns, "dynamicOutputs": {}}
                    for p, ns in dependencies.items()
                },
            },
        }
        data["inventory"][drv] = {
            "drv_path": drv,
            "outputs": {"out": out if addressing == "ia" else None},
            "input_sources": [],
            "input_derivations": dependencies,
        }
        data["collect"]["output_paths"][drv + "^out"] = out
        data["paths"][out] = {
            "required": True,
            "prebuild_valid": False,
            "collection_status": "valid",
            "hook_invocations": ["hook-1"],
            "roles": [
                "root-output" if name == "root" else "build-input-output"
            ],
        }
        info = {
            "version": 2,
            "storeDir": "/nix/store",
            "narHash": "sha256-test-" + name,
            "narSize": 42,
            "references": [Path(path(d, digit)).name for d in deps],
        }
        if seed:
            info["narHash"] = "sha256-seeded-" + name
            info["unseeded"] = {
                "path": Path(path(name)).name,
                "narHash": "sha256-test-" + name,
                "narSize": 42,
                "references": [Path(path(d)).name for d in deps],
            }
        data["realized-path-info"][out] = info
    return data


def repeat(data):
    data = copy.deepcopy(data)
    data["manifest"]["run_id"] = str(uuid.uuid4())
    return data


class CompareTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def write(self, name, data):
        directory = self.base / name
        directory.mkdir()
        for artifact, value in data.items():
            (directory / (artifact + ".json")).write_text(json.dumps(value))
        return directory

    def compare(self, left, right):
        return comparator.compare(
            self.write("left", left), self.write("right", right)
        )

    def write_signed(self, name, data, claims=None):
        data = copy.deepcopy(data)
        data["manifest"]["public_key"] = PUBLIC_KEY
        for drv in data["inventory"]:
            out = data["collect"]["output_paths"][drv + "^out"]
            if not data["paths"][out]["prebuild_valid"]:
                data["paths"][out]["hook_invocations"] = [Path(drv).stem]
        directory = self.write(name, data)
        cache = self.base / (name + "-cache")
        traces = cache / "traces" / "aterm"
        traces.mkdir(parents=True)
        mode = data["manifest"]["addressing"]
        for drv in data["inventory"]:
            recipe = data["derivations"]["derivations"][Path(drv).name]
            if "hash" in recipe["outputs"]["out"]:
                continue
            claim = (claims or {}).get(recipe["name"], {})
            out = data["collect"]["output_paths"][drv + "^out"]
            rdrv = drv if mode == "ia" else path(recipe["name"] + ".drv", "8")
            hook = data["paths"][out]["hook_invocations"][0]
            observation = directory / "observations" / hook
            observation.mkdir(parents=True)
            (observation / "status.json").write_text(json.dumps({
                "invocation": hook, "drv_path": rdrv, "out_paths": [out],
                "status": "complete", "sign_exit_status": 0, "errors": [],
            }))
            resolved = claim.get("resolved_input", HASH)
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": "out", "digest": claim.get("digest", {
                    "nix-ca-store-path": path(recipe["name"], "1"),
                    "nix-nar-sha256": "ab" * 32,
                    "snix-castore-entry": "-_8",
                })}],
                "predicate": {
                    "buildDefinition": {
                        "buildType": BUILD_TYPES[mode],
                        "externalParameters": {
                            "resolvedInput": {"digest": {"aterm": resolved}},
                            "criticalFeatures": [],
                        },
                    },
                    "runDetails": {
                        "builder": {"id": BUILDER},
                        "metadata": {"invocationId": "a" * 32},
                        "byproducts": [{
                            "name": "laut-debug-preimage",
                            "mediaType": "application/json",
                            "content": encode({
                                "rdrv_path": rdrv,
                                "rdrv_aterm_ca_preimage": claim.get("aterm", ATERM),
                            }),
                        }],
                    },
                },
            }
            bundle = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"publicKey": {"hint": HINT}},
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": encode(statement),
                    # Deliberately unauthenticated, like the helper fixtures.
                    "signatures": [{"keyid": HINT, "sig": encode(bytes(64))}],
                },
            }
            with (traces / resolved).open("a") as stream:
                stream.write(json.dumps(bundle) + "\n")
        return directory, cache

    def test_repeat_is_only_metadata_agreement_and_dependency_first(self):
        a = fixture()
        report, code = self.compare(a, repeat(a))
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "baseline-agreement")
        self.assertEqual(
            [n["name"] for n in report["nodes"]], ["tool", "root"]
        )
        self.assertEqual(report["equivalence"], "untested")
        for node in report["nodes"]:
            self.assertEqual(node["normalized_inputs"], "untested")
            self.assertEqual(node["synthetic_identity"], "untested")
            self.assertEqual(node["outputs"]["out"]["status"], "equal")

    def test_same_directory_and_aliases_are_not_repeats(self):
        directory = self.write("state", fixture())
        alias = self.base / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        for right in (directory, directory / ".." / "state", alias):
            with self.subTest(right=right):
                report, code = comparator.compare(directory, right)
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "invalid")
                self.assertIn(
                    "same artifact directory", report["invalid_reason"]
                )
                self.assertEqual(report["nodes"], [])

    def test_copied_run_id_is_not_a_repeat(self):
        a = fixture()
        b = copy.deepcopy(a)
        b["manifest"]["hostname"] = "another-builder"
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "invalid")
        self.assertIn("same run_id", report["invalid_reason"])
        self.assertEqual(report["nodes"], [])

    def test_run_id_is_observational(self):
        left = self.write("left", fixture())
        right = self.write("right", fixture())
        for sides in ((left, right), (right, left)):
            report, code = comparator.compare(*sides)
            self.assertEqual(code, 0)
            self.assertEqual(report["status"], "baseline-agreement")

    def test_current_manifest_fields_are_required_on_both_sides(self):
        for field in ("schema_version", "run_id"):
            with self.subTest(field=field):
                a, b = fixture(), fixture()
                del b["manifest"][field]
                left = self.write("left-" + field, a)
                right = self.write("right-" + field, b)
                for sides in ((left, right), (right, left)):
                    report, code = comparator.compare(*sides)
                    self.assertEqual(code, 1)
                    self.assertEqual(report["nodes"], [])
                    self.assertTrue(
                        any(
                            field in error["error"]
                            for error in report["errors"]
                        )
                    )

    def test_manifest_schema_version_must_be_integer_one(self):
        for index, version in enumerate((None, 0, 2, "1", True, 1.0)):
            with self.subTest(version=version):
                a, b = fixture(), fixture()
                b["manifest"]["schema_version"] = version
                report, code = comparator.compare(
                    self.write(f"left-{index}", a),
                    self.write(f"right-{index}", b),
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["nodes"], [])
                self.assertTrue(
                    any(
                        "expected manifest schema_version=1" in error["error"]
                        for error in report["errors"]
                    )
                )

    def test_run_id_must_be_a_nonempty_string(self):
        for index, run_id in enumerate((None, "", 42)):
            with self.subTest(run_id=run_id):
                a, b = fixture(), fixture()
                b["manifest"]["run_id"] = run_id
                report, code = comparator.compare(
                    self.write(f"left-{index}", a),
                    self.write(f"right-{index}", b),
                )
                self.assertEqual(code, 1)
                self.assertTrue(
                    any(
                        "invalid manifest run_id" in error["error"]
                        for error in report["errors"]
                    )
                )

    def test_divergent_leaf_blocks_parent_but_not_independent_branch(self):
        a = fixture(graph={"root": ["tool", "other"], "tool": [], "other": []})
        b = repeat(a)
        b["realized-path-info"][path("tool")]["narHash"] = "different"
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        nodes = {n["name"]: n for n in report["nodes"]}
        self.assertEqual(nodes["tool"]["status"], "divergent")
        self.assertEqual(nodes["other"]["status"], "evidence-agrees")
        self.assertEqual(nodes["root"]["status"], "blocked")
        self.assertEqual(nodes["root"]["outputs"], {})
        self.assertEqual(nodes["root"]["blocked_by"], [path("tool.drv")])

    def test_cross_seed_uses_nix_records_against_empty_seed_actual(self):
        report, code = self.compare(fixture(), fixture(seed="A", digit="1"))
        self.assertEqual(code, 0)
        out = report["nodes"][0]["outputs"]["out"]
        self.assertNotEqual(out["left"]["actual"], out["right"]["actual"])
        self.assertEqual(out["left"]["compared"], out["right"]["compared"])
        self.assertEqual(out["right"]["basis"], "nix-unseeded")

    def test_cross_seed_difference_is_not_normalized_away(self):
        a, b = fixture(), fixture(seed="A", digit="1")
        b["realized-path-info"][path("tool", "1")]["unseeded"][
            "references"
        ] = [path("extra").split("/")[-1]]
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(
            report["nodes"][0]["outputs"]["out"]["differences"], ["references"]
        )
        self.assertEqual(report["nodes"][-1]["status"], "blocked")

    def test_repeat_does_not_use_unseeded_to_hide_actual_difference(self):
        a = fixture(seed="A", digit="1")
        b = repeat(a)
        b["realized-path-info"][path("tool", "1")]["narSize"] += 1
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(
            report["nodes"][0]["outputs"]["out"]["differences"], ["narSize"]
        )

    def test_missing_unseeded_field_blocks_dependents(self):
        for field in ("unseeded", "path", "narHash", "narSize", "references"):
            with self.subTest(field=field):
                a, b = fixture(), fixture(seed="A", digit="1")
                info = b["realized-path-info"][path("tool", "1")]
                if field == "unseeded":
                    del info[field]
                else:
                    del info["unseeded"][field]
                report, code = comparator.compare(
                    self.write("left-" + field, a),
                    self.write("right-" + field, b),
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["nodes"][0]["status"], "missing")
                self.assertEqual(report["nodes"][-1]["status"], "blocked")

    def test_missing_required_artifacts_fail_closed(self):
        for artifact in fixture():
            with self.subTest(artifact=artifact):
                a, b = fixture(), fixture()
                del b[artifact]
                report, code = comparator.compare(
                    self.write("left-" + artifact, a),
                    self.write("right-" + artifact, b),
                )
                self.assertEqual(code, 1)
                self.assertTrue(report["errors"])

    def test_incomplete_collection_errors_are_preserved(self):
        a, b = fixture(), fixture()
        error = {
            "artifact": "contents:0",
            "required": True,
            "error": "copy failed",
        }
        b["collect"].update(status="incomplete", errors=[error])
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(
            report["collection"]["right"]["collect"]["errors"], [error]
        )

    def test_malformed_collection_is_reported_not_a_traceback(self):
        for index, value in enumerate(
            (
                None,
                [],
                {"status": "complete", "errors": None},
                {"status": "complete", "errors": [None]},
            )
        ):
            with self.subTest(value=value):
                a, b = fixture(), fixture()
                b["collect"] = value
                report, code = comparator.compare(
                    self.write(f"left-{index}", a),
                    self.write(f"right-{index}", b),
                )
                self.assertEqual(code, 1)
                self.assertTrue(report["errors"])

    def test_optional_collection_errors_remain_visible(self):
        a, b = fixture(), fixture()
        error = {
            "artifact": "unused-output",
            "required": False,
            "error": "absent",
        }
        b["collect"]["errors"] = [error]
        report, code = self.compare(a, b)
        self.assertEqual(code, 0)
        self.assertEqual(
            report["collection"]["right"]["collect"]["errors"], [error]
        )

    def test_missing_output_and_unobserved_output_fail(self):
        for missing in ("realization", "metadata", "hook"):
            with self.subTest(missing=missing):
                a, b = fixture(), fixture()
                if missing == "realization":
                    del b["collect"]["output_paths"][path("tool.drv") + "^out"]
                elif missing == "metadata":
                    del b["realized-path-info"][path("tool")]
                else:
                    b["paths"][path("tool")]["hook_invocations"] = []
                report, code = comparator.compare(
                    self.write("left-" + missing, a),
                    self.write("right-" + missing, b),
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["nodes"][0]["status"], "missing")

    def test_missing_source_evidence_blocks_its_dependents(self):
        a = fixture()
        source = path("source")
        a["derivations"]["derivations"][Path(path("tool.drv")).name]["inputs"][
            "srcs"
        ] = [Path(source).name]
        a["inventory"][path("tool.drv")]["input_sources"] = [source]
        a["paths"][source] = {
            "required": True,
            "prebuild_valid": True,
            "collection_status": "valid",
            "hook_invocations": [],
            "roles": ["input-source"],
        }
        a["realized-path-info"][source] = copy.deepcopy(
            a["realized-path-info"][path("tool")]
        )
        b = repeat(a)
        del b["realized-path-info"][source]
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(report["nodes"][0]["status"], "missing")
        self.assertEqual(report["nodes"][-1]["status"], "blocked")

    def test_runtime_reference_absent_from_collection_fails(self):
        a = fixture()
        a["realized-path-info"][path("tool")]["references"] = [
            Path(path("absent")).name
        ]
        report, code = self.compare(a, repeat(a))
        self.assertEqual(code, 1)
        self.assertTrue(report["errors"])

    def test_sibling_repeated_names_are_ambiguous_even_with_same_paths(self):
        a = fixture(
            graph={"root": ["first", "second"], "first": [], "second": []},
            names={"first": "duplicate", "second": "duplicate"},
        )
        report, code = self.compare(a, repeat(a))
        self.assertEqual(code, 1)
        self.assertEqual(report["nodes"][0]["status"], "ambiguous")
        self.assertEqual(len(report["unpaired"]["left"]), 2)
        self.assertEqual(report["correspondence"][0]["status"], "ambiguous")

    def test_repeated_names_in_separate_rooted_branches_can_pair(self):
        graph = {"root": ["a", "b"], "a": ["x"], "b": ["y"], "x": [], "y": []}
        a = fixture(graph=graph, names={"x": "same", "y": "same"})
        b = fixture(
            digit="1", seed="A", graph=graph, names={"x": "same", "y": "same"}
        )
        report, code = self.compare(a, b)
        self.assertEqual(code, 0)
        self.assertEqual(len(report["nodes"]), 5)

    def test_shared_dependency_cannot_pair_with_two_nodes(self):
        a = fixture(
            graph={"root": ["a", "b"], "a": ["x"], "b": ["x"], "x": []}
        )
        b = fixture(
            graph={
                "root": ["a", "b"],
                "a": ["x"],
                "b": ["y"],
                "x": [],
                "y": [],
            },
            names={"y": "x"},
        )
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertTrue(
            any(p["status"] == "ambiguous" for p in report["correspondence"])
        )
        self.assertNotEqual(report["nodes"][-1]["status"], "evidence-agrees")

    def test_global_unique_names_do_not_override_different_parent_relation(
        self,
    ):
        a = fixture(graph={"root": ["a", "b"], "a": ["x"], "b": [], "x": []})
        b = fixture(graph={"root": ["a", "b"], "a": [], "b": ["x"], "x": []})
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertIn(path("x.drv"), report["unpaired"]["left"])

    def test_requested_and_declared_output_names_constrain_pairing(self):
        tool, root = Path(path("tool.drv")).name, Path(path("root.drv")).name
        for changed in ("requested", "declared"):
            with self.subTest(changed=changed):
                a, b = fixture(), fixture()
                for data in (a, b):
                    data["derivations"]["derivations"][tool]["outputs"][
                        "dev"
                    ] = {}
                    data["inventory"][path("tool.drv")]["outputs"][
                        "dev"
                    ] = None
                if changed == "requested":
                    b["derivations"]["derivations"][root]["inputs"]["drvs"][
                        tool
                    ]["outputs"] = ["dev"]
                    b["inventory"][path("root.drv")]["input_derivations"][
                        path("tool.drv")
                    ] = ["dev"]
                else:
                    del b["derivations"]["derivations"][tool]["outputs"]["dev"]
                    del b["inventory"][path("tool.drv")]["outputs"]["dev"]
                report, code = comparator.compare(
                    self.write("left-" + changed, a),
                    self.write("right-" + changed, b),
                )
                self.assertEqual(code, 1)
                self.assertTrue(report["correspondence"])

    def test_ia_ca_identical_ordinary_nars_are_never_compared(self):
        report, code = self.compare(fixture(), fixture(addressing="ca"))
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "unsupported")
        self.assertTrue(all(n["outputs"] == {} for n in report["nodes"]))
        self.assertTrue(
            all(
                n["synthetic_identity"] == "unsupported"
                for n in report["nodes"]
            )
        )

    def test_two_nonempty_seeds_need_baseline(self):
        report, code = self.compare(fixture(seed="A"), fixture(seed="B"))
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "unsupported")

    def test_mismatched_controls_are_invalid(self):
        for control in (*comparator.CONTROLS, "nixpkgs"):
            with self.subTest(control=control):
                a, b = fixture(), fixture()
                if control == "nixpkgs":
                    b["manifest"][control]["source"] = path("other-source")
                else:
                    b["manifest"][control] += "-different"
                report, code = comparator.compare(
                    self.write("left-" + control, a),
                    self.write("right-" + control, b),
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "invalid")
                self.assertEqual(report["nodes"], [])

    def test_preloaded_fod_mapping_is_boundary_not_build_evidence(self):
        a, b = fixture(), fixture(seed="A", digit="1")
        ca = {"method": "flat", "hash": "sha256-fixed"}
        for data, digit in ((a, "0"), (b, "1")):
            drv, out = path("tool.drv", digit), path("tool", digit)
            data["derivations"]["derivations"][Path(drv).name]["outputs"][
                "out"
            ] = ca
            data["paths"][out].update(prebuild_valid=True, hook_invocations=[])
            info = data["realized-path-info"][out]
            info.pop("unseeded", None)
            info.update(
                ca=ca if data["manifest"]["seed"] else None,
                narHash="sha256-fixed-nar",
            )
        b["seeded-inputs"] = {
            path("tool"): {
                "seeded": path("tool", "1"),
                "ca": ca,
                "narHash": "sha256-fixed-nar",
                "narSize": 42,
            }
        }
        report, code = self.compare(a, b)
        self.assertEqual(code, 0)
        output = report["nodes"][0]["outputs"]["out"]
        self.assertEqual(output["right"]["basis"], "seeded-inputs-boundary")
        self.assertEqual(
            output["synthetic_comparison"], "excluded-fixed-output-boundary"
        )
        self.assertTrue(output["right"]["preloaded"])
        for field in (
            "ca",
            "narHash",
            "narSize",
            "references",
            "realized-ca-null",
            "realized-ca-missing",
        ):
            with self.subTest(inconsistent_mapping=field):
                broken = copy.deepcopy(b)
                info = broken["realized-path-info"][path("tool", "1")]
                if field == "references":
                    info[field] = [Path(path("tool", "1")).name]
                elif field == "realized-ca-null":
                    info["ca"] = None
                elif field == "realized-ca-missing":
                    del info["ca"]
                else:
                    broken["seeded-inputs"][path("tool")][field] = "different"
                report, code = comparator.compare(
                    self.base / "left", self.write("broken-" + field, broken)
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["nodes"][0]["status"], "missing")

    def test_preloaded_fod_without_mapping_is_missing_not_actual_fallback(
        self,
    ):
        a, b = fixture(), fixture(seed="A", digit="1")
        for data, digit in ((a, "0"), (b, "1")):
            drv, out = path("tool.drv", digit), path("tool", digit)
            data["derivations"]["derivations"][Path(drv).name]["outputs"][
                "out"
            ] = {"method": "flat", "hash": "sha256-fixed"}
            data["paths"][out].update(prebuild_valid=True, hook_invocations=[])
            data["realized-path-info"][out].pop("unseeded", None)
        report, code = self.compare(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(report["nodes"][0]["status"], "missing")
        self.assertIn(
            "seeded-inputs",
            report["nodes"][0]["outputs"]["out"]["right"]["error"],
        )

    def test_reference_order_is_irrelevant_but_actual_paths_are_not(self):
        a = fixture(graph={"root": ["a", "b"], "a": [], "b": []})
        b = repeat(a)
        b["realized-path-info"][path("root")]["references"].reverse()
        report, code = comparator.compare(
            self.write("left-order", a), self.write("right-order", b)
        )
        self.assertEqual(code, 0)
        report, code = self.compare(fixture(), fixture(digit="1"))
        self.assertEqual(code, 1)
        self.assertEqual(
            report["nodes"][0]["outputs"]["out"]["differences"], ["path"]
        )

    def test_cross_seed_baseline_can_be_on_right(self):
        report, code = self.compare(fixture(seed="A", digit="1"), fixture())
        self.assertEqual(code, 0)
        out = report["nodes"][0]["outputs"]["out"]
        self.assertEqual(out["left"]["basis"], "nix-unseeded")
        self.assertEqual(out["right"]["basis"], "actual")

    def test_ca_repeat_uses_collected_realizations(self):
        a = fixture(addressing="ca")
        report, code = self.compare(a, repeat(a))
        self.assertEqual(code, 0)
        self.assertEqual(
            report["nodes"][0]["outputs"]["out"]["status"], "equal"
        )

    def test_cli_writes_json_and_explicit_limited_summary(self):
        left, right = self.write("left", fixture()), self.write(
            "right", fixture()
        )
        output = self.base / "report"
        console = io.StringIO()
        with contextlib.redirect_stdout(console):
            code = comparator.main(
                [
                    "--left",
                    str(left),
                    "--right",
                    str(right),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads((output / "report.json").read_text())["equivalence"],
            "untested",
        )
        self.assertIn("NOT established", console.getvalue())

    def test_signed_ia_ca_agreement_ignores_ordinary_nar_differences(self):
        a, b = fixture(), fixture(addressing="ca", digit="1")
        for info in b["realized-path-info"].values():
            info.update(narHash="sha256-rewritten-ca", narSize=123)
        left, left_cache = self.write_signed("left", a)
        right, right_cache = self.write_signed("right", b)
        for sides in ((left, right, left_cache, right_cache),
                      (right, left, right_cache, left_cache)):
            with self.subTest(left=sides[0]):
                report, code = comparator.compare(*sides)
                self.assertEqual(code, 0)
                self.assertEqual(report["status"], "diagnostic-agreement")
                self.assertEqual(report["scope"], "ia-ca")
                self.assertEqual(report["errors"], [])
                self.assertEqual(report["signed_claims"], "diagnostic")
                self.assertFalse(report["authenticated"])
                self.assertEqual(report["signature_verification"], "untested")
                self.assertEqual(report["equivalence"], "untested")
                self.assertEqual(report["synthetic_nar_size"],
                                 "unavailable-in-signed-identity")
                self.assertEqual(len(report["nodes"]), 2)
                for node in report["nodes"]:
                    self.assertEqual(node["status"], "evidence-agrees")
                    self.assertEqual(node["outputs"], {})
                    self.assertEqual(node["normalized_inputs"], "equal")
                    self.assertEqual(node["synthetic_identity"], "equal")
                    self.assertEqual(node["signed_outputs"]["out"], {
                        "status": "equal", "differences": [],
                    })
                    for side in ("left", "right"):
                        evidence = node["signed_evidence"][side]
                        self.assertEqual(evidence["aterm"], ATERM)
                        self.assertEqual(evidence["resolved_input"], HASH)
                        self.assertTrue(evidence["outputs"]["out"])
                        provenance = evidence["provenance"]
                        self.assertTrue(provenance["hook_observation_ids"])
                        if provenance["build_type"] == BUILD_TYPES["ca"]:
                            self.assertNotEqual(provenance["rdrv_path"],
                                                provenance["inventory_drv"])

    def test_each_signed_output_digest_diverges_independently(self):
        left, left_cache = self.write_signed("left", fixture(graph={"root": []}))
        digest = {
            "nix-ca-store-path": path("root", "1"),
            "nix-nar-sha256": "ab" * 32,
            "snix-castore-entry": "-_8",
        }
        for field, value in (
            ("nix-ca-store-path", path("root", "2")),
            ("nix-nar-sha256", "cd" * 32),
            ("snix-castore-entry", encode(b"different")),
        ):
            with self.subTest(field=field):
                right, right_cache = self.write_signed(
                    field, fixture(graph={"root": []}),
                    {"root": {"digest": {**digest, field: value}}},
                )
                report, code = comparator.compare(
                    left, right, left_cache, right_cache
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["errors"], [])
                node, = report["nodes"]
                self.assertEqual(node["status"], "divergent")
                self.assertEqual(node["outputs"]["out"]["status"], "equal")
                self.assertEqual(node["normalized_inputs"], "equal")
                self.assertEqual(node["synthetic_identity"], "divergent")
                self.assertEqual(node["signed_outputs"]["out"], {
                    "status": "divergent", "differences": [field],
                })

    def test_exact_aterm_and_resolved_hash_are_compared_independently(self):
        left, left_cache = self.write_signed("left", fixture(graph={"root": []}))
        for field, value in (("aterm", ATERM.rstrip("\n")),
                             ("resolved_input", "2" * 32)):
            with self.subTest(field=field):
                right, right_cache = self.write_signed(
                    field, fixture(graph={"root": []}), {"root": {field: value}},
                )
                report, code = comparator.compare(
                    left, right, left_cache, right_cache
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["errors"], [])
                node, = report["nodes"]
                self.assertEqual(node["status"], "divergent")
                self.assertEqual(node["input_differences"], [field])
                self.assertEqual(node["normalized_inputs"], "divergent")
                self.assertEqual(node["synthetic_identity"], "equal")
                if field == "resolved_input":
                    with mock.patch.object(comparator.subprocess, "run") as run:
                        comparator.write_preimages(report, self.base / field)
                    run.assert_not_called()
                    for side in ("left", "right"):
                        self.assertEqual(
                            Path(node["preimage_artifacts"][side]).read_bytes(),
                            ATERM.encode(),
                        )

    def test_blocked_nodes_retain_signed_evidence_and_independent_branch(self):
        graph = {"root": ["parent", "other"], "parent": ["tool"],
                 "tool": [], "other": []}
        left, left_cache = self.write_signed("left", fixture(graph=graph))
        right, right_cache = self.write_signed(
            "right", fixture(addressing="ca", digit="1", graph=graph),
            {name: {"aterm": ATERM + "\n"}
             for name in ("tool", "parent", "root")},
        )
        report, code = comparator.compare(left, right, left_cache, right_cache)
        self.assertEqual(code, 1)
        self.assertEqual(report["errors"], [])
        nodes = {n["name"]: n for n in report["nodes"]}
        self.assertEqual(nodes["tool"]["status"], "divergent")
        self.assertEqual(nodes["tool"]["attribution"], "local")
        self.assertEqual(nodes["other"]["status"], "evidence-agrees")
        self.assertEqual(nodes["other"]["synthetic_identity"], "equal")
        for name, dependency in (("parent", "tool"), ("root", "parent")):
            node = nodes[name]
            self.assertEqual(node["status"], "blocked")
            self.assertEqual(node["blocked_by"], [path(dependency + ".drv")])
            self.assertEqual(node["attribution"], "blocked")
            self.assertEqual(node["input_differences"], ["aterm"])
            self.assertEqual(node["normalized_inputs"], "divergent")
            self.assertEqual(node["signed_outputs"]["out"]["status"], "equal")
            self.assertEqual(node["signed_evidence"]["left"]["aterm"], ATERM)
            self.assertEqual(
                node["signed_evidence"]["right"]["aterm"], ATERM + "\n"
            )

    def test_signed_comparison_excludes_preloaded_fod_without_bundle(self):
        a = fixture()
        drv, out = path("tool.drv"), path("tool")
        a["derivations"]["derivations"][Path(drv).name]["outputs"]["out"] = {
            "method": "flat", "hash": "sha256-fixed",
        }
        a["paths"][out].update(prebuild_valid=True, hook_invocations=[])
        left, left_cache = self.write_signed("left", a)
        right, right_cache = self.write_signed("right", repeat(a))
        report, code = comparator.compare(left, right, left_cache, right_cache)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "diagnostic-agreement")
        boundary, root = report["nodes"]
        self.assertEqual(boundary["name"], "tool")
        self.assertEqual(boundary["status"], "evidence-agrees")
        self.assertNotIn("signed_evidence", boundary)
        for field in ("normalized_inputs", "synthetic_identity"):
            self.assertEqual(boundary[field], "excluded-fixed-output-boundary")
        self.assertEqual(boundary["outputs"]["out"]["status"], "equal")
        self.assertEqual(root["normalized_inputs"], "equal")
        self.assertEqual(root["synthetic_identity"], "equal")
        self.assertEqual(root["blocked_by"], [])

    def test_missing_side_preserves_available_preimage(self):
        left, left_cache = self.write_signed("left", fixture(graph={"root": []}))
        right, right_cache = self.write_signed("right", fixture(graph={"root": []}))
        (right_cache / "traces" / "aterm" / HASH).unlink()
        for sides, available in (
            ((left, right, left_cache, right_cache), "left"),
            ((right, left, right_cache, left_cache), "right"),
        ):
            with self.subTest(available=available):
                report, code = comparator.compare(*sides)
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "failed")
                node, = report["nodes"]
                self.assertEqual(node["status"], "missing")
                self.assertEqual(node["normalized_inputs"], "missing")
                self.assertEqual(node["synthetic_identity"], "missing")
                self.assertEqual(node["signed_outputs"], {})
                missing = "right" if available == "left" else "left"
                self.assertIn("found 0", node["signed_evidence"][missing]["error"])
                with mock.patch.object(comparator.subprocess, "run") as run:
                    comparator.write_preimages(
                        report, self.base / available / "report"
                    )
                run.assert_not_called()
                artifacts = node["preimage_artifacts"]
                self.assertEqual(set(artifacts), {available})
                preimage = Path(artifacts[available])
                self.assertEqual(preimage.read_bytes(), ATERM.encode())
                self.assertFalse(
                    (preimage.parent / (missing + ".aterm")).exists()
                )

    def test_empty_or_missing_signed_evidence_never_agrees(self):
        digest = {
            "nix-ca-store-path": path("root", "1"),
            "nix-nar-sha256": "ab" * 32,
            "snix-castore-entry": "-_8",
        }
        cases = [("empty-cache", {}), ("empty-aterm", {"aterm": ""}),
                 ("empty-digests", {"digest": {}})]
        for field in digest:
            cases.append(("missing-" + field, {
                "digest": {k: v for k, v in digest.items() if k != field},
            }))
            cases.append(("empty-" + field, {"digest": {**digest, field: ""}}))
        for label, claim in cases:
            with self.subTest(case=label):
                left, left_cache = self.write_signed(
                    label + "-left", fixture(graph={"root": []}), {"root": claim},
                )
                right, right_cache = self.write_signed(
                    label + "-right", fixture(graph={"root": []}), {"root": claim},
                )
                if label == "empty-cache":
                    for cache in (left_cache, right_cache):
                        (cache / "traces" / "aterm" / HASH).unlink()
                report, code = comparator.compare(
                    left, right, left_cache, right_cache
                )
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "failed")
                node, = report["nodes"]
                self.assertEqual(node["status"], "missing")
                self.assertEqual(node["normalized_inputs"], "missing")
                self.assertEqual(node["synthetic_identity"], "missing")
                for evidence in node["signed_evidence"].values():
                    self.assertIn("error", evidence)

    def test_cli_cache_options_reject_missing_or_one_sided_cache(self):
        left, left_cache = self.write_signed("left", fixture(graph={"root": []}))
        right, right_cache = self.write_signed("right", fixture(graph={"root": []}))
        missing = self.base / "absent-cache"
        for index, (lc, rc) in enumerate((
            (left_cache, None), (None, right_cache),
            (left_cache, missing), (missing, right_cache),
        )):
            with self.subTest(left_cache=lc, right_cache=rc):
                report, code = comparator.compare(left, right, lc, rc)
                self.assertEqual(code, 1)
                if lc is None or rc is None:
                    self.assertEqual(report["status"], "invalid")
                    self.assertEqual(
                        report["invalid_reason"], "both caches required"
                    )
                else:
                    self.assertEqual(report["status"], "failed")
                    self.assertTrue(report["errors"])
                output = self.base / ("report-" + str(index))
                args = ["--left", str(left), "--right", str(right),
                        "--output", str(output)]
                for flag, cache in (("--left-cache", lc), ("--right-cache", rc)):
                    if cache is not None:
                        args.extend([flag, str(cache)])
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(comparator.main(args), 1)
                written = json.loads((output / "report.json").read_text())
                self.assertEqual(written["status"], report["status"])

    def test_cli_caches_write_preimages_and_difft_artifacts_or_errors(self):
        left, left_cache = self.write_signed("left", fixture(graph={"root": []}))
        for label, aterm, result in (
            ("equal", ATERM, None),
            ("different", ATERM + "\n", (0, b"structural difference\n", b"")),
            ("failed", ATERM + "\n", (2, b"partial diff\n", b"difft error\n")),
            ("unavailable", ATERM + "\n", FileNotFoundError("difft not installed")),
        ):
            with self.subTest(case=label):
                right, right_cache = self.write_signed(
                    label, fixture(graph={"root": []}), {"root": {"aterm": aterm}},
                )
                output = self.base / (label + "-report")
                console = io.StringIO()
                with mock.patch.object(comparator.subprocess, "run") as run:
                    if isinstance(result, Exception):
                        run.side_effect = result
                    elif result is not None:
                        run.return_value = comparator.subprocess.CompletedProcess(
                            [], *result,
                        )
                    with contextlib.redirect_stdout(console):
                        code = comparator.main([
                            "--left", str(left), "--right", str(right),
                            "--left-cache", str(left_cache),
                            "--right-cache", str(right_cache),
                            "--output", str(output),
                        ])
                self.assertEqual(code, 0 if label == "equal" else 1)
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(
                    report["status"],
                    "diagnostic-agreement" if label == "equal" else "failed",
                )
                self.assertIn("NOT established", console.getvalue())
                node, = report["nodes"]
                artifacts = node["preimage_artifacts"]
                for side, expected in (("left", ATERM), ("right", aterm)):
                    preimage = Path(artifacts[side])
                    self.assertTrue(preimage.is_relative_to(output / "preimages"))
                    self.assertEqual(preimage.read_bytes(), expected.encode())
                if label == "equal":
                    run.assert_not_called()
                    self.assertEqual(set(artifacts), {"left", "right"})
                else:
                    run.assert_called_once_with(
                        ["difft", "--color=never", "--display=inline",
                         "--override=*:Python",
                         artifacts["left"], artifacts["right"]],
                        capture_output=True, check=False,
                    )
                    if isinstance(result, tuple):
                        diff = Path(artifacts["diff"])
                        self.assertEqual(
                            diff.parent, Path(artifacts["left"]).parent
                        )
                        self.assertEqual(diff.read_bytes(), result[1])
                        self.assertEqual(
                            (diff.parent / "difft.stderr").read_bytes(), result[2]
                        )
                        self.assertEqual(artifacts["difft_exit_status"], result[0])
                    else:
                        self.assertNotIn("diff", artifacts)
                if label in ("failed", "unavailable"):
                    error, = report["errors"]
                    self.assertEqual(
                        error["artifact"], str(Path(artifacts["left"]).parent)
                    )
                    self.assertIn(
                        "exit 2" if label == "failed" else "not installed",
                        error["error"],
                    )
                else:
                    self.assertEqual(report["errors"], [])


if __name__ == "__main__":
    unittest.main()
