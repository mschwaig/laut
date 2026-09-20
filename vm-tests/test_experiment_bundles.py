"""Offline fixtures for unauthenticated signed-claim extraction."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from experiment_bundles import BUILD_TYPES, load_bundles, signed_evidence


PUBLIC_KEY = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="
BUILDER = (
    "urn:laut:builder:sha256:"
    "bcda8d54470fea3b4e22071ddf53ef79bc1a75bab562f83cefb4e0660e4f4877"
)
HINT = "SHA256:h8w3leuTqqQXWFb3jSqxN2RyER5JZLb0drUjn2vJXTo"
HASH = "0" * 32
DRV = f"/nix/store/{'1' * 32}-recipe.drv"
RESOLVED_DRV = f"/nix/store/{HASH}-recipe.drv"
OUT = f"/nix/store/{'2' * 32}-recipe"
DEV = f"/nix/store/{'3' * 32}-recipe-dev"
SYNTHETIC = f"/nix/store/{'4' * 32}-recipe"
ATERM = 'Derive([("out","","r:sha256","")],[],[],"system","builder",[],[])\n'


def encode(value):
    if not isinstance(value, bytes):
        value = json.dumps(value).encode()
    return base64.b64encode(value).decode()


class BundlesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "cache"
        self.traces = self.cache / "traces" / "aterm"
        self.traces.mkdir(parents=True)
        self.directory = self.root / "experiment"
        self.manifest = {"public_key": PUBLIC_KEY, "addressing": "ia"}
        self.data = {
            "manifest": self.manifest, "required": {DRV: {"out"}},
            "collect": {"output_paths": {DRV + "^out": OUT}},
            "paths": {OUT: {"hook_invocations": ["hook-1"]}},
        }
        self.debug = {"rdrv_path": DRV, "rdrv_aterm_ca_preimage": ATERM}
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "out", "digest": {
                "nix-ca-store-path": SYNTHETIC, "nix-nar-sha256": "ab" * 32,
                "snix-castore-entry": "-_8",
            }}],
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPES["ia"],
                    "externalParameters": {
                        "resolvedInput": {"digest": {"aterm": HASH}},
                        "criticalFeatures": [],
                    },
                },
                "runDetails": {
                    "builder": {"id": BUILDER},
                    "metadata": {"invocationId": "a" * 32},
                    "byproducts": [],
                },
            },
        }
        self.status = {
            "invocation": "hook-1", "drv_path": DRV, "out_paths": [OUT],
            "status": "complete", "sign_exit_status": 0, "errors": [],
        }
        self.write_status()

    def write_status(self, status=None):
        status = self.status if status is None else status
        directory = self.directory / "observations" / status["invocation"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "status.json").write_text(json.dumps(status))

    def bundle(self):
        self.statement["predicate"]["runDetails"]["byproducts"] = [{
            "name": "laut-debug-preimage", "mediaType": "application/json",
            "content": encode(self.debug),
        }]
        return {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"publicKey": {"hint": HINT}},
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": encode(self.statement),
                # Invalid signature: this API never authenticates.
                "signatures": [{"keyid": HINT, "sig": encode(bytes(64))}],
            },
        }

    def write_bundles(self, *bundles, filename=HASH):
        raw = b"".join(json.dumps(b).encode() + b"\n" for b in bundles)
        (self.traces / filename).write_bytes(raw)
        return raw

    def extract(self):
        return signed_evidence(self.directory, self.data, DRV,
                               load_bundles(self.cache, self.manifest))

    def use_ca(self):
        self.manifest["addressing"] = "ca"
        self.statement["predicate"]["buildDefinition"]["buildType"] = (
            BUILD_TYPES["ca"]
        )
        self.statement["subject"][0]["digest"]["nix-ca-store-path"] = OUT
        self.debug["rdrv_path"] = RESOLVED_DRV
        self.status["drv_path"] = RESOLVED_DRV
        self.write_status()

    def test_ia_exact_claims_and_provenance_without_authentication(self):
        raw = self.write_bundles(self.bundle())
        result = self.extract()
        self.assertEqual(
            set(result), {"resolved_input", "aterm", "outputs", "provenance"}
        )
        self.assertEqual(result["resolved_input"], HASH)
        self.assertEqual(result["aterm"], ATERM)
        self.assertEqual(result["outputs"]["out"], {
            "nix-ca-store-path": SYNTHETIC, "nix-nar-sha256": "ab" * 32,
            "snix-castore-entry": "+/8=",
        })
        provenance = result["provenance"]
        self.assertFalse(provenance["authenticated"])
        self.assertEqual(provenance["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance["cache_path"], str(self.traces / HASH))
        self.assertEqual(provenance["line"], 1)
        self.assertEqual(provenance["builder"], BUILDER)
        self.assertEqual(provenance["key_hint"], HINT)
        self.assertEqual(provenance["invocation"], "a" * 32)
        self.assertEqual(provenance["hook_observation_ids"], ["hook-1"])
        json.dumps(result)

    def test_ca_joins_resolved_hook_not_inventory_drv(self):
        self.use_ca()
        self.write_bundles(self.bundle())
        result = self.extract()
        self.assertEqual(result["provenance"]["rdrv_path"], RESOLVED_DRV)
        self.assertNotEqual(RESOLVED_DRV, DRV)
        self.assertEqual(result["outputs"]["out"]["nix-ca-store-path"], OUT)

    def test_filters_other_builder_and_preserves_line_number(self):
        selected = self.bundle()
        foreign = copy.deepcopy(selected)
        statement = copy.deepcopy(self.statement)
        statement["predicate"]["runDetails"]["builder"]["id"] = "other-builder"
        foreign["verificationMaterial"]["publicKey"]["hint"] = "other-hint"
        foreign["dsseEnvelope"]["payload"] = encode(statement)
        self.write_bundles(foreign, selected)
        self.assertEqual(self.extract()["provenance"]["line"], 2)
        self.write_bundles(foreign)
        with self.assertRaisesRegex(ValueError, "found 0"):
            self.extract()

    def test_wrong_builder_or_hint_is_not_silently_skipped(self):
        for field in ("builder", "hint", "signature-hint"):
            with self.subTest(field=field):
                bundle = self.bundle()
                if field == "builder":
                    statement = copy.deepcopy(self.statement)
                    statement["predicate"]["runDetails"]["builder"]["id"] = (
                        "wrong"
                    )
                    bundle["dsseEnvelope"]["payload"] = encode(statement)
                elif field == "hint":
                    bundle["verificationMaterial"]["publicKey"]["hint"] = (
                        "wrong"
                    )
                else:
                    bundle["dsseEnvelope"]["signatures"][0]["keyid"] = "wrong"
                self.write_bundles(bundle)
                with self.assertRaisesRegex(ValueError, "hint"):
                    self.extract()

    def test_missing_or_duplicate_bundle_and_distinct_attempts(self):
        with self.assertRaisesRegex(ValueError, "found 0"):
            self.extract()
        bundle = self.bundle()
        for invocation in ("a" * 32, "b" * 32):
            with self.subTest(invocation=invocation):
                run = self.statement["predicate"]["runDetails"]
                run["metadata"]["invocationId"] = invocation
                self.write_bundles(bundle, self.bundle())
                with self.assertRaisesRegex(ValueError, "found 2"):
                    self.extract()

    def test_wrong_hash_filename(self):
        self.write_bundles(self.bundle(), filename="1" * 32)
        with self.assertRaisesRegex(ValueError, "filename"):
            self.extract()

    def test_wrong_mode(self):
        self.statement["predicate"]["buildDefinition"]["buildType"] = (
            BUILD_TYPES["ca"]
        )
        self.write_bundles(self.bundle())
        with self.assertRaisesRegex(ValueError, "buildType"):
            self.extract()

    def test_wrong_debug_hook(self):
        self.debug["rdrv_path"] = RESOLVED_DRV
        self.write_bundles(self.bundle())
        with self.assertRaisesRegex(ValueError, "found 0"):
            self.extract()

    def test_ia_matching_hook_and_claim_must_use_inventory_drv(self):
        self.debug["rdrv_path"] = RESOLVED_DRV
        self.status["drv_path"] = RESOLVED_DRV
        self.write_status()
        self.write_bundles(self.bundle())
        with self.assertRaisesRegex(ValueError, "IA hook derivation"):
            self.extract()

    def test_missing_hook_ids_or_status(self):
        self.write_bundles(self.bundle())
        self.data["paths"][OUT]["hook_invocations"] = []
        with self.assertRaisesRegex(ValueError, "found 0"):
            self.extract()
        self.data["paths"][OUT]["hook_invocations"] = ["missing"]
        with self.assertRaises(FileNotFoundError):
            self.extract()

    def test_invalid_hook_status(self):
        self.write_bundles(self.bundle())
        for field, value in (
            ("status", "partial"), ("sign_exit_status", 1),
            ("sign_exit_status", 117), ("sign_exit_status", False),
            ("errors", ["failed"]), ("errors", None),
        ):
            with self.subTest(field=field, value=value):
                self.write_status({**self.status, field: value})
                with self.assertRaisesRegex(ValueError, "successfully"):
                    self.extract()

    def test_hook_id_must_match_status_directory(self):
        self.write_bundles(self.bundle())
        path = self.directory / "observations" / "hook-1" / "status.json"
        path.write_text(json.dumps({**self.status, "invocation": "other"}))
        with self.assertRaisesRegex(ValueError, "invocation"):
            self.extract()

    def test_exact_out_paths_membership(self):
        self.write_bundles(self.bundle())
        for paths in ([], [DEV], [OUT, DEV], [OUT, OUT], OUT):
            with self.subTest(paths=paths):
                self.write_status({**self.status, "out_paths": paths})
                with self.assertRaisesRegex(ValueError, "OUT_PATHS"):
                    self.extract()

    def test_named_subject_coverage(self):
        subject = copy.deepcopy(self.statement["subject"][0])
        for subjects in (
            [], [{**subject, "name": "dev"}],
            [subject, {**subject, "name": "dev"}], [subject, subject],
        ):
            with self.subTest(subjects=subjects):
                self.statement["subject"] = subjects
                self.write_bundles(self.bundle())
                with self.assertRaises(ValueError):
                    self.extract()

    def test_ca_wrong_realized_output(self):
        self.use_ca()
        self.statement["subject"][0]["digest"]["nix-ca-store-path"] = SYNTHETIC
        self.write_bundles(self.bundle())
        with self.assertRaisesRegex(ValueError, "CA output"):
            self.extract()

    def test_multiple_noops_do_not_imply_multiple_signed_attempts(self):
        self.use_ca()
        self.write_bundles(self.bundle())
        for number, exit_status in enumerate((0, 117), 2):
            hook = f"hook-{number}"
            self.data["paths"][OUT]["hook_invocations"].append(hook)
            self.write_status({
                **self.status, "invocation": hook,
                "drv_path": DRV, "sign_exit_status": exit_status,
            })
        provenance = self.extract()["provenance"]
        self.assertEqual(provenance["hook_observation_ids"], ["hook-1"])
        self.assertEqual(len(provenance["expected_hook_observation_ids"]), 3)

    def test_two_matching_hooks_are_ambiguous_even_with_one_bundle(self):
        self.write_bundles(self.bundle())
        self.data["paths"][OUT]["hook_invocations"].append("hook-2")
        self.write_status({**self.status, "invocation": "hook-2"})
        with self.assertRaisesRegex(ValueError, "found 2"):
            self.extract()

    def test_hook_intersection_not_union_for_multiple_outputs(self):
        self.data["required"][DRV].add("dev")
        self.data["collect"]["output_paths"][DRV + "^dev"] = DEV
        self.data["paths"][DEV] = {"hook_invocations": ["hook-1"]}
        self.data["paths"][OUT]["hook_invocations"].append("out-only")
        self.status["out_paths"] = [DEV, OUT]
        self.write_status()
        self.statement["subject"].append({
            "name": "dev",
            "digest": copy.deepcopy(self.statement["subject"][0]["digest"]),
        })
        self.write_bundles(self.bundle())
        self.assertEqual(set(self.extract()["outputs"]), {"out", "dev"})
        self.data["paths"][DEV]["hook_invocations"] = ["dev-only"]
        with self.assertRaisesRegex(ValueError, "found 0"):
            self.extract()

    def test_malformed_base64_at_every_consumed_location(self):
        for value in (
            "", "!!!!", "A", "Zg=", "Zg===", "Zh==", "Z g==", "\u00e9"
        ):
            for location in ("payload", "signature", "debug", "castore"):
                with self.subTest(value=value, location=location):
                    bundle = self.bundle()
                    if location == "payload":
                        bundle["dsseEnvelope"]["payload"] = value
                    elif location == "signature":
                        bundle["dsseEnvelope"]["signatures"][0]["sig"] = value
                    else:
                        statement = copy.deepcopy(self.statement)
                        if location == "debug":
                            run = statement["predicate"]["runDetails"]
                            run["byproducts"][0]["content"] = value
                        else:
                            digest = statement["subject"][0]["digest"]
                            digest["snix-castore-entry"] = value
                        bundle["dsseEnvelope"]["payload"] = encode(statement)
                    self.write_bundles(bundle)
                    with self.assertRaises(ValueError):
                        self.extract()

    def test_base64_alphabets_and_padding_canonicalize(self):
        for value in ("+/8=", "-_8=", "+/8", "-_8"):
            with self.subTest(value=value):
                digest = self.statement["subject"][0]["digest"]
                digest["snix-castore-entry"] = value
                self.write_bundles(self.bundle())
                self.assertEqual(
                    self.extract()["outputs"]["out"]["snix-castore-entry"],
                    "+/8=",
                )

    def test_exactly_one_debug_preimage(self):
        for count in (0, 2):
            with self.subTest(count=count):
                bundle = self.bundle()
                run = self.statement["predicate"]["runDetails"]
                run["byproducts"] *= count
                bundle["dsseEnvelope"]["payload"] = encode(self.statement)
                self.write_bundles(bundle)
                with self.assertRaisesRegex(ValueError, "exactly one debug"):
                    self.extract()

    def test_empty_or_missing_identities_and_preimage(self):
        for field in (
            "aterm", "nix-ca-store-path", "nix-nar-sha256",
            "snix-castore-entry", "preimage",
        ):
            for value in (None, "", 42):
                with self.subTest(field=field, value=value):
                    bundle = self.bundle()
                    statement = copy.deepcopy(self.statement)
                    if field == "aterm":
                        build = statement["predicate"]["buildDefinition"]
                        params = build["externalParameters"]
                        params["resolvedInput"]["digest"][field] = value
                    elif field == "preimage":
                        run = statement["predicate"]["runDetails"]
                        run["byproducts"][0]["content"] = encode({
                            **self.debug, "rdrv_aterm_ca_preimage": value,
                        })
                    else:
                        statement["subject"][0]["digest"][field] = value
                    bundle["dsseEnvelope"]["payload"] = encode(statement)
                    self.write_bundles(bundle)
                    with self.assertRaises(ValueError):
                        self.extract()

    def test_malformed_json_and_duplicate_keys(self):
        for raw in (b"\n", b"{", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.subTest(raw=raw):
                (self.traces / HASH).write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.extract()
        bundle = self.bundle()
        bundle["dsseEnvelope"]["payload"] = encode(
            b'{"predicate":{},"predicate":{}}'
        )
        self.write_bundles(bundle)
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            self.extract()

    def test_invalid_public_key(self):
        for key in (
            "", "no-colon", "builder:!!!", "builder:" + encode(bytes(31))
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    load_bundles(
                        self.cache, {**self.manifest, "public_key": key}
                    )

    def test_consumed_profile_fields(self):
        params = ("predicate", "buildDefinition", "externalParameters")
        invocation = ("predicate", "runDetails", "metadata", "invocationId")
        cases = (
            (("_type",), "wrong"),
            (("predicateType",), "wrong"),
            (invocation, ""),
            (invocation, "A" * 32),
            (params, {}),
            ((*params, "extra"), 1),
            ((*params, "criticalFeatures"), ["x", "x"]),
            ((*params, "criticalFeatures"), [None]),
            (("subject",), {}),
        )
        for keys, value in cases:
            with self.subTest(keys=keys, value=value):
                bundle = self.bundle()
                statement = copy.deepcopy(self.statement)
                target = statement
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                bundle["dsseEnvelope"]["payload"] = encode(statement)
                self.write_bundles(bundle)
                with self.assertRaises(ValueError):
                    self.extract()

    def test_missing_required_realization_and_empty_request(self):
        self.write_bundles(self.bundle())
        del self.data["collect"]["output_paths"][DRV + "^out"]
        with self.assertRaises(KeyError):
            self.extract()
        self.data["required"][DRV] = set()
        with self.assertRaisesRegex(ValueError, "no required outputs"):
            self.extract()

    def test_malformed_optional_resource_fields(self):
        cases = [
            (field, value)
            for field in (
                "name", "uri", "downloadLocation", "mediaType", "content"
            )
            for value in (42, False, [], {})
        ] + [
            ("annotations", value) for value in ("", 42, False, [])
        ] + [("content", "not base64!")]
        for location in ("resolvedInput", "subject"):
            for field, value in cases:
                with self.subTest(location=location, field=field, value=value):
                    bundle = self.bundle()
                    statement = copy.deepcopy(self.statement)
                    build = statement["predicate"]["buildDefinition"]
                    resource = (
                        build["externalParameters"]["resolvedInput"]
                        if location == "resolvedInput"
                        else statement["subject"][0]
                    )
                    resource[field] = value
                    bundle["dsseEnvelope"]["payload"] = encode(statement)
                    self.write_bundles(bundle)
                    with self.assertRaises(ValueError):
                        self.extract()

    def test_valid_optional_resource_fields(self):
        build = self.statement["predicate"]["buildDefinition"]
        resolved = build["externalParameters"]["resolvedInput"]
        for text, content, annotations in (
            (None, None, None), ("", "", {}),
            ("resource", "-_8", {"extra": [None, 42]}),
        ):
            with self.subTest(text=text, content=content):
                resolved["name"] = text
                for resource in (resolved, self.statement["subject"][0]):
                    resource.update(
                        uri=text, downloadLocation=text, mediaType=text,
                        content=content, annotations=annotations,
                    )
                self.write_bundles(self.bundle())
                self.assertFalse(self.extract()["provenance"]["authenticated"])

    def test_builder_version_is_optional_string_map(self):
        builder = self.statement["predicate"]["runDetails"]["builder"]
        for version in (None, {}, {"nixVersion": "2.35", "extra": ""}):
            with self.subTest(version=version):
                builder["version"] = version
                self.write_bundles(self.bundle())
                self.assertFalse(self.extract()["provenance"]["authenticated"])
        for version in ("", [], False, {"nixVersion": 42}, {"extra": None}):
            with self.subTest(version=version):
                builder["version"] = version
                self.write_bundles(self.bundle())
                with self.assertRaisesRegex(ValueError, "builder version"):
                    self.extract()

    def test_duplicate_hook_ids_are_not_collapsed(self):
        self.write_bundles(self.bundle())
        self.data["paths"][OUT]["hook_invocations"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate hook"):
            self.extract()

    def test_missing_digest_schemes_and_empty_digest_maps(self):
        for field in (
            "nix-ca-store-path", "nix-nar-sha256", "snix-castore-entry", None
        ):
            with self.subTest(field=field):
                bundle = self.bundle()
                statement = copy.deepcopy(self.statement)
                digest = statement["subject"][0]["digest"]
                if field is None:
                    digest.clear()
                else:
                    del digest[field]
                bundle["dsseEnvelope"]["payload"] = encode(statement)
                self.write_bundles(bundle)
                with self.assertRaises(ValueError):
                    self.extract()


if __name__ == "__main__":
    unittest.main()
