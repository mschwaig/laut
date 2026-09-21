"""Diagnostic extraction of current laut Sigstore claims, NOT authentication.

No signatures, contents, or ATerm hashes are verified or recomputed. The only
hashing here identifies public keys and records the source JSONL bytes.
"""

import base64
import hashlib
import json
from pathlib import Path
import re

from experiment import derivations, inventory_entry, path_info


BUILD_TYPES = {
    mode: (
        "https://github.com/mschwaig/laut/blob/main/docs/"
        "slsa-provenance-v1.md#"
        + suffix
    )
    for mode, suffix in (("ca", "ca"), ("ia", "synthetic-ia"))
}
NIX_HASH = r"[0-9abcdfghijklmnpqrsvwxyz]{32}"
STORE_PATH = rf"/nix/store/{NIX_HASH}-[A-Za-z0-9+._?=-]+"


def _text(value):
    if not isinstance(value, str) or not value:
        raise ValueError("expected nonempty string")
    return value


def _match(pattern, value):
    if not re.fullmatch(pattern, _text(value)):
        raise ValueError(f"invalid identity: {value!r}")
    return value


def _decode(value):
    # Match attestation.rs: either alphabet, padded or unpadded, no junk or
    # nonzero trailing bits. Python's decoder alone permits the latter.
    text = _text(value).replace("-", "+").replace("_", "/")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        raise ValueError("malformed base64")
    bare = text.rstrip("=")
    padded = bare + "=" * (-len(bare) % 4)
    if "=" in text and text != padded:
        raise ValueError("malformed base64 padding")
    decoded = base64.b64decode(padded, validate=True)
    if base64.b64encode(decoded).decode() != padded:
        raise ValueError("noncanonical base64 trailing bits")
    return decoded


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(raw):
    def invalid(value):
        raise ValueError(f"invalid JSON constant: {value}")

    value = json.loads(raw, object_pairs_hook=_object, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _digests(resource):
    if not isinstance(resource, dict):
        raise ValueError("invalid resource descriptor")
    for name in ("name", "uri", "downloadLocation", "mediaType", "content"):
        value = resource.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"invalid resource {name}")
    annotations = resource.get("annotations")
    if annotations is not None and not isinstance(annotations, dict):
        raise ValueError("invalid resource annotations")
    if resource.get("content"):
        _decode(resource["content"])
    digests = resource["digest"]
    if not isinstance(digests, dict) or not digests:
        raise ValueError("missing identities")
    for key, value in digests.items():
        _text(key)
        _text(value)
    return digests


def load_bundles(cache: Path, manifest: dict) -> dict:
    """Index selected-builder claims by debug rdrv_path, retaining every line.

    `cache` is the cache root, not traces/aterm. The index contains `by_drv`
    (lists of evidence dictionaries), `builder`, `key_hint`, and `build_type`.
    Malformed selected evidence raises ValueError (I/O errors propagate).
    A different builder is skipped only if neither its ID nor hint selects us.
    """
    label, separator, encoded = _text(manifest["public_key"]).partition(":")
    if not label or not separator:
        raise ValueError("expected Nix public key name:base64")
    public_key = _decode(encoded)
    if len(public_key) != 32:
        raise ValueError("expected 32-byte Ed25519 public key")
    fingerprint = hashlib.sha256(
        bytes.fromhex("302a300506032b6570032100") + public_key
    ).hexdigest()
    builder = "urn:laut:builder:sha256:" + fingerprint
    hint = "SHA256:" + base64.b64encode(hashlib.sha256(
        b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + public_key
    ).digest()).decode().rstrip("=")
    if manifest["addressing"] not in BUILD_TYPES:
        raise ValueError("unknown addressing mode")
    build_type = BUILD_TYPES[manifest["addressing"]]
    index = {"builder": builder, "key_hint": hint,
             "build_type": build_type, "by_drv": {}}
    for path in sorted((cache / "traces" / "aterm").iterdir()):
        with path.open("rb") as stream:
            for line, raw in enumerate(stream, 1):
                try:
                    bundle = _json(raw)
                    if bundle["mediaType"] != (
                        "application/vnd.dev.sigstore.bundle.v0.3+json"
                    ):
                        raise ValueError("unexpected bundle mediaType")
                    envelope = bundle["dsseEnvelope"]
                    if envelope["payloadType"] != (
                        "application/vnd.in-toto+json"
                    ):
                        raise ValueError("unexpected payloadType")
                    statement = _json(_decode(envelope["payload"]))
                    predicate = statement["predicate"]
                    run = predicate["runDetails"]
                    claimed_builder = _text(run["builder"]["id"])
                    claimed_hint = _text(
                        bundle["verificationMaterial"]["publicKey"]["hint"]
                    )
                    if claimed_builder != builder and claimed_hint != hint:
                        continue
                    if claimed_builder != builder or claimed_hint != hint:
                        raise ValueError(
                            "builder/key hint does not match manifest"
                        )
                    versions = run["builder"].get("version")
                    if versions is not None and (
                        not isinstance(versions, dict)
                        or not all(isinstance(v, str)
                                   for v in versions.values())
                    ):
                        raise ValueError("invalid builder version")
                    signatures = envelope["signatures"]
                    if (not isinstance(signatures, list)
                            or len(signatures) != 1):
                        raise ValueError("expected one DSSE signature")
                    if (signatures[0]["keyid"] != hint
                            or len(_decode(signatures[0]["sig"])) != 64):
                        raise ValueError("invalid signature shape/key hint")
                    if (
                        statement["_type"] != "https://in-toto.io/Statement/v1"
                        or statement["predicateType"]
                        != "https://slsa.dev/provenance/v1"
                    ):
                        raise ValueError("unexpected statement profile")
                    build = predicate["buildDefinition"]
                    if build["buildType"] != build_type:
                        raise ValueError(
                            "buildType does not match manifest mode"
                        )
                    params = build["externalParameters"]
                    if not isinstance(params, dict) or params.keys() - {
                        "resolvedInput", "criticalFeatures"
                    }:
                        raise ValueError("unknown externalParameters")
                    features = params.get("criticalFeatures")
                    if features is not None and (
                        not isinstance(features, list)
                        or not all(isinstance(f, str) for f in features)
                        or len(set(features)) != len(features)
                    ):
                        raise ValueError("malformed criticalFeatures")
                    resolved = _match(
                        NIX_HASH, _digests(params["resolvedInput"])["aterm"]
                    )
                    if path.name != resolved:
                        raise ValueError(
                            "cache filename differs from signed resolved input"
                        )
                    invocation = _match(
                        r"[0-9a-f]{32}", run["metadata"]["invocationId"]
                    )
                    byproducts = run["byproducts"]
                    if not isinstance(byproducts, list) or not all(
                        isinstance(p, dict) for p in byproducts
                    ):
                        raise ValueError("invalid byproducts")
                    preimages = [
                        p for p in byproducts
                        if p.get("name") == "laut-debug-preimage"
                    ]
                    if (
                        len(preimages) != 1
                        or preimages[0]["mediaType"] != "application/json"
                    ):
                        raise ValueError(
                            "expected exactly one debug preimage"
                        )
                    debug = _json(_decode(preimages[0]["content"]))
                    rdrv = _match(STORE_PATH + r"\.drv", debug["rdrv_path"])
                    aterm = _text(debug["rdrv_aterm_ca_preimage"])
                    subjects = statement["subject"]
                    if not isinstance(subjects, list) or not subjects:
                        raise ValueError("missing named output subjects")
                    outputs = {}
                    for subject in subjects:
                        name = _text(subject["name"])
                        if name in outputs:
                            raise ValueError(
                                "duplicate named output subject"
                            )
                        digests = _digests(subject)
                        outputs[name] = {
                            "nix-ca-store-path": _match(
                                STORE_PATH, digests["nix-ca-store-path"]
                            ),
                            "nix-nar-sha256": _match(
                                r"[0-9a-f]{64}", digests["nix-nar-sha256"]
                            ),
                            "snix-castore-entry": base64.b64encode(
                                _decode(digests["snix-castore-entry"])
                            ).decode(),
                        }
                    evidence = {
                        "resolved_input": resolved,
                        "aterm": aterm, "outputs": outputs,
                        "provenance": {
                            "authenticated": False, "cache_path": str(path),
                            "line": line,
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "builder": builder, "key_hint": hint,
                            "invocation": invocation,
                            "build_type": build_type,
                            "critical_features": features or [],
                            "rdrv_path": rdrv,
                        },
                    }
                    index["by_drv"].setdefault(rdrv, []).append(evidence)
                except (
                    ValueError, KeyError, TypeError, AttributeError
                ) as error:
                    raise ValueError(f"{path}:{line}: {error}") from error
    return index


def signed_evidence(
    directory: Path, data: dict, drv: str, index: dict
) -> dict:
    """Join a comparator node to exactly one bundle and one hook observation.

    `data` is comparator-loaded data, including required[drv] output names,
    collect.output_paths, and paths. Hooks producing extra outputs require a
    complete inventory/output snapshot join before projecting required outputs.
    IA paths come from the hook inventory, not synthetic signed CA identities;
    CA paths come from the named subjects and must cover the observed paths.
    Unmatched hooks can be no-ops. Every CA candidate must have resolved inputs
    matching the original recipe's sources plus its collected dependency
    outputs. This is a necessary input-linkage check, not recipe/hash
    authentication. Multiple surviving hooks or JSONL entries remain ambiguous,
    even if equal.
    Provenance SHA256 covers the exact JSONL line bytes, including its newline.
    Hook UUIDs and signed invocation IDs are distinct identifiers.
    """
    names = data["required"][drv]
    if not names:
        raise ValueError(f"no required outputs: {drv}")
    realized = {
        name: _match(
            STORE_PATH, data["collect"]["output_paths"][drv + "^" + name]
        )
        for name in names
    }
    hook_sets = []
    for path in realized.values():
        hooks = data["paths"][path]["hook_invocations"]
        if not isinstance(hooks, list):
            raise ValueError("invalid hook_invocations")
        for hook in hooks:
            _match(r"[A-Za-z0-9_-]+", hook)
        if len(set(hooks)) != len(hooks):
            raise ValueError("duplicate hook observation ID")
        hook_sets.append(set(hooks))
    expected_hooks = set.intersection(*hook_sets)
    matches = []
    for hook in sorted(expected_hooks):
        status_path = directory / "observations" / hook / "status.json"
        status = _json(status_path.read_bytes())
        if status["invocation"] != hook:
            raise ValueError(f"hook invocation differs from directory: {hook}")
        rdrv = _match(STORE_PATH + r"\.drv", status["drv_path"])
        candidates = index["by_drv"].get(rdrv, [])
        if not candidates:
            continue
        if index["build_type"] == BUILD_TYPES["ia"] and rdrv != drv:
            raise ValueError("IA hook derivation differs from inventory drv")
        if (status["status"] != "complete"
                or type(status["sign_exit_status"]) is not int
                or status["sign_exit_status"] != 0
                or not isinstance(status["errors"], list)
                or status["errors"]):
            raise ValueError(f"hook did not complete successfully: {hook}")
        out_paths = status["out_paths"]
        if (not isinstance(out_paths, list)
                or not all(isinstance(p, str) for p in out_paths)
                or len(out_paths) != len(set(out_paths))
                or not set(realized.values()) <= set(out_paths)):
            raise ValueError(
                f"hook OUT_PATHS missing or invalid required outputs: {hook}"
            )
        declared = realized
        if set(out_paths) != set(realized.values()):
            observation = status_path.parent
            inventory = _json((observation / "inventory.json").read_bytes())
            declared = inventory["outputs"]
            if (inventory["drv_path"] != rdrv
                    or not isinstance(declared, dict)
                    or declared.keys()
                    != data["inventory"][drv]["outputs"].keys()
                    or not realized.keys() <= declared.keys()):
                raise ValueError("hook output inventory differs from graph")
            info = path_info(
                (observation / "output-path-info.json").read_bytes())
            if (info.keys() != set(out_paths)
                    or any(value is None for value in info.values())):
                raise ValueError("hook output snapshot differs from OUT_PATHS")
        for evidence in candidates:
            outputs = evidence["outputs"]
            if outputs.keys() != declared.keys():
                raise ValueError(
                    "signed subjects differ from hook output names"
                )
            produced = declared
            if index["build_type"] == BUILD_TYPES["ca"]:
                produced = {name: output["nix-ca-store-path"]
                            for name, output in outputs.items()}
                if any(path is not None and produced[name] != path
                       for name, path in declared.items()):
                    raise ValueError(
                        "signed CA output differs from realized output"
                    )
            for path in produced.values():
                _match(STORE_PATH, path)
            if (len(set(produced.values())) != len(produced)
                    or set(produced.values()) != set(out_paths)
                    or any(produced[name] != path
                           for name, path in realized.items())):
                raise ValueError(
                    "hook output mapping differs from "
                    "OUT_PATHS/required outputs"
                )
            matches.append((hook, evidence))
    linkage = {}
    if index["build_type"] == BUILD_TYPES["ca"]:
        original = data["inventory"][drv]
        sources = set(original["input_sources"])
        sources.update(
            _match(STORE_PATH,
                   data["collect"]["output_paths"][dep + "^" + name])
            for dep, requested in original["input_derivations"].items()
            for name in requested
        )
        hook_sources = {}
        for hook, evidence in matches:
            if hook in hook_sources:
                continue
            observation = directory / "observations" / hook
            entry = _json((observation / "inventory.json").read_bytes())
            recipes = derivations(
                (observation / "derivation.json").read_bytes())
            rdrv = evidence["provenance"]["rdrv_path"]
            raw = (observation / "derivation.aterm").read_bytes()
            if (set(recipes) != {rdrv}
                    or inventory_entry(rdrv, recipes[rdrv], raw) != entry):
                raise ValueError(
                    f"hook inventory differs from raw recipe: {hook}")
            if entry["input_derivations"]:
                raise ValueError(
                    f"CA hook recipe still has input derivations: {hook}")
            hook_sources[hook] = sorted(entry["input_sources"])
        # Input sets only exclude incompatible recipes. Never deduplicate
        # observations/bundles with equal recipes, claims, or invocation IDs.
        matches = [(hook, evidence) for hook, evidence in matches
                   if set(hook_sources[hook]) == sources]
        linkage = {"recipe_linkage": {
            "expected_input_sources": sorted(sources),
            "hook_input_sources": hook_sources,
        }}
    if len(matches) != 1:
        raise ValueError(
            f"expected one bundle/hook match for {drv}, found {len(matches)}"
        )
    hook, evidence = matches[0]
    return {
        **evidence,
        "outputs": {name: evidence["outputs"][name] for name in names},
        "provenance": {
            **evidence["provenance"], **linkage, "inventory_drv": drv,
            "hook_observation_ids": [hook],
            "expected_hook_observation_ids": sorted(expected_hooks),
            "hook_status_path": str(
                directory / "observations" / hook / "status.json"
            ),
            "realized_outputs": realized,
        },
    }
