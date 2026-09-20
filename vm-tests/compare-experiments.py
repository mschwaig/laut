"""Offline, unauthenticated experiment comparisons, not trust admission.

Run: python3 vm-tests/compare-experiments.py \
    --left STATE --right STATE --output DIR
Add --left-cache CACHE --right-cache CACHE to compare signed claims and exact
normalized ATerms diagnostically. Requires difft for structural diff artifacts.
Writes DIR/report.json. Exit 0 means only the selected evidence agrees;
1 means invalid, missing, ambiguous or divergent evidence; 2 means unsupported.
No contents, signatures, or identity hashes are recomputed/verified.
Source contents and synthetic NAR sizes remain untested.
Manifests must have schema_version=1 and a nonempty run_id. Known
self-comparisons are rejected; distinct IDs do not prove independent builds.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from experiment import derivations, read_json, store_path
from experiment_bundles import load_bundles, signed_evidence


ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError)
CONTROLS = ("target", "system", "nixPackage", "nixRevision", "laut-sign-only")
OBSERVATIONAL = {
    "id",
    "hostname",
    "public_key",
    "root_drv",
    "addressing",
    "seed",
    "run_id",
}


def identity(path, info):
    """Compare recorded fields verbatim, except reference set ordering."""
    store_path(path)
    if not isinstance(info["narHash"], str) or not info["narHash"]:
        raise ValueError("missing NAR hash")
    if type(info["narSize"]) is not int or info["narSize"] < 0:
        raise ValueError("missing NAR size")
    if not isinstance(info["references"], list):
        raise ValueError("missing reference set")
    return {
        "path": path,
        "narHash": info["narHash"],
        "narSize": info["narSize"],
        "references": sorted(
            {store_path(p, basename=True) for p in info["references"]}
        ),
    }


def load(directory, side, report):
    data = {}
    for name in (
        "manifest",
        "begin",
        "inventory",
        "derivations",
        "collect",
        "realized-path-info",
        "paths",
        "seeded-inputs",
    ):
        file = directory / (name + ".json")
        if name == "seeded-inputs" and not file.exists():
            data[name] = {}
            continue
        try:
            data[name] = read_json(file)
            if not isinstance(data[name], dict):
                raise ValueError("expected a JSON object")
        except ERRORS as error:
            report["errors"].append(
                {"side": side, "artifact": name, "error": str(error)}
            )
    report["collection"][side] = {
        name: data.get(name) for name in ("begin", "collect")
    }
    for name in ("begin", "collect"):
        status = data.get(name, {})
        try:
            if (
                status.get("status") != "complete"
                or not isinstance(status["errors"], list)
                or any(e.get("required", True) for e in status["errors"])
                or status.get("unresolved_outputs")
            ):
                raise ValueError("collection is incomplete")
        except ERRORS as error:
            report["errors"].append(
                {"side": side, "artifact": name, "error": str(error)}
            )
    try:
        manifest = data["manifest"]
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
        ):
            raise ValueError("expected manifest schema_version=1")
        for key in (*CONTROLS, "addressing", "seed", "run_id"):
            if not isinstance(manifest[key], str) or (
                key != "seed" and not manifest[key]
            ):
                raise ValueError(f"invalid manifest {key}")
        for key in ("source", "revision"):
            if (
                not isinstance(manifest["nixpkgs"][key], str)
                or not manifest["nixpkgs"][key]
            ):
                raise ValueError(f"missing nixpkgs {key}")
        if manifest["addressing"] not in ("ia", "ca"):
            raise ValueError("unknown addressing mode")
        drvs = derivations(json.dumps(data["derivations"]))
        inventory = data["inventory"]
        if drvs.keys() != inventory.keys() or manifest["root_drv"] not in drvs:
            raise ValueError("incomplete original graph inventory")
        required = {p: set() for p in drvs}
        required[manifest["root_drv"]].update(
            drvs[manifest["root_drv"]]["outputs"]
        )
        for path, drv in drvs.items():
            if not isinstance(drv["name"], str) or not drv["name"]:
                raise ValueError("missing original recipe name")
            entry = inventory[path]
            deps = {
                store_path(p, True): d["outputs"]
                for p, d in drv["inputs"]["drvs"].items()
            }
            sources = [store_path(p, True) for p in drv["inputs"]["srcs"]]
            if (
                entry["drv_path"] != path
                or entry["outputs"].keys() != drv["outputs"].keys()
                or entry["input_derivations"] != deps
                or entry["input_sources"] != sources
            ):
                raise ValueError(
                    f"inventory differs from original JSON: {path}"
                )
            for name, output in drv["outputs"].items():
                if (
                    "path" in output
                    and store_path(output["path"], True)
                    != entry["outputs"][name]
                ):
                    raise ValueError(
                        "inventory differs from declared output: "
                        f"{path}^{name}"
                    )
            for dep, names in deps.items():
                if (
                    not isinstance(names, list)
                    or not names
                    or not set(names) <= drvs[dep]["outputs"].keys()
                ):
                    raise ValueError(f"invalid requested outputs: {dep}")
                required[dep].update(names)
            for source in sources:
                if not data["paths"][source]["required"]:
                    raise ValueError(
                        f"source not collected as required: {source}"
                    )
        data["drvs"], data["required"] = drvs, required
        for path, item in data["paths"].items():
            if not item["required"]:
                continue
            try:
                recorded = actual(data, path)
                for reference in recorded["references"]:
                    if not data["paths"][reference]["required"]:
                        raise ValueError(
                            f"reference not collected as required: {reference}"
                        )
                if (
                    not item["prebuild_valid"]
                    and not item["hook_invocations"]
                    and {"root-output", "build-input-output"}.intersection(
                        item["roles"]
                    )
                ):
                    raise ValueError("new output has no hook observation")
            except ERRORS as error:
                report["errors"].append(
                    {"side": side, "artifact": path, "error": str(error)}
                )
        return data
    except ERRORS as error:
        report["errors"].append(
            {"side": side, "artifact": "schema", "error": str(error)}
        )
        return None


def actual(data, path):
    if data["paths"][path]["collection_status"] != "valid":
        raise ValueError("path collection is not valid")
    info = data["realized-path-info"][path]
    if info["version"] != 2 or info["storeDir"] != "/nix/store":
        raise ValueError("expected /nix/store path-info v2")
    return identity(path, info)


def output_evidence(data, drv, name, cross_seed):
    path = data["collect"]["output_paths"][drv + "^" + name]
    declared = data["inventory"][drv]["outputs"][name]
    if declared is not None and declared != path:
        raise ValueError("declared output differs from collected realization")
    item = data["paths"][path]
    if not item["required"]:
        raise ValueError("output not collected as required")
    recorded = actual(data, path)
    fod = "hash" in data["drvs"][drv]["outputs"][name]
    result = {
        "actual": recorded,
        "preloaded": item["prebuild_valid"],
        "hook_invocations": item["hook_invocations"],
        "boundary": "fixed-output" if fod else None,
        "basis": "actual",
    }
    if not item["prebuild_valid"] and not item["hook_invocations"]:
        raise ValueError("new output has no hook observation")
    canonical = recorded
    if cross_seed and data["manifest"]["seed"]:
        if fod and item["prebuild_valid"]:
            mappings = [
                (p, m)
                for p, m in data["seeded-inputs"].items()
                if m["seeded"] == path
            ]
            if len(mappings) != 1:
                raise ValueError(
                    "preloaded FOD needs a unique seeded-inputs mapping"
                )
            original, mapping = mappings[0]
            info = data["realized-path-info"][path]
            if (
                recorded["references"]
                or mapping["ca"] != info["ca"]
                or any(
                    mapping[k] != recorded[k] for k in ("narHash", "narSize")
                )
            ):
                raise ValueError(
                    "seeded-inputs mapping differs from collected FOD"
                )
            canonical = identity(original, {**mapping, "references": []})
            result["basis"] = "seeded-inputs-boundary"
        else:
            unseeded = data["realized-path-info"][path]["unseeded"]
            canonical = identity(store_path(unseeded["path"], True), unseeded)
            result["basis"] = "nix-unseeded"
    result["compared"] = canonical
    return result


def compare(left, right, left_cache=None, right_cache=None):
    claims = left_cache is not None and right_cache is not None
    report = {
        "version": 1,
        "status": "missing",
        "scope": None,
        "equivalence": "untested",
        "authenticated": False,
        "signed_claims": "diagnostic" if claims else "untested",
        "signature_verification": "untested",
        "synthetic_nar_size": "unavailable-in-signed-identity",
        "directories": {"left": str(left), "right": str(right)},
        "errors": [],
        "collection": {},
        "correspondence": [],
        "nodes": [],
    }
    a, b = load(left, "left", report), load(right, "right", report)
    if a is None or b is None:
        return report, 1
    if (left_cache is None) != (right_cache is None):
        report.update(status="invalid", invalid_reason="both caches required")
        return report, 1
    ma, mb = a["manifest"], b["manifest"]
    report["manifests"] = {"left": ma, "right": mb}
    reason = None
    if left.resolve() == right.resolve():
        reason = "left and right resolve to the same artifact directory"
    elif ma["run_id"] == mb["run_id"]:
        reason = "left and right have the same run_id (copied run artifacts)"
    if reason:
        report.update(status="invalid", invalid_reason=reason)
        return report, 1
    controls = (ma.keys() | mb.keys()) - OBSERVATIONAL
    differences = sorted(k for k in controls if ma.get(k) != mb.get(k))
    if differences:
        report.update(status="invalid", configuration_differences=differences)
        return report, 1
    cross_mode = ma["addressing"] != mb["addressing"]
    cross_seed = ma["seed"] != mb["seed"]
    unsupported = (cross_mode and not claims) or (
        cross_seed and bool(ma["seed"] and mb["seed"])
    )
    report["scope"] = (
        "ia-ca" if cross_mode else "cross-seed" if cross_seed else "repeat"
    )
    if unsupported:
        report["unsupported"] = (
            "IA/CA requires existing laut synthetic identity extraction; "
            "ordinary NARs are not comparable"
            if cross_mode
            else "cross-seed comparison requires one empty-seed baseline"
        )

    indexes = {}
    if claims:
        for side, cache, manifest in (
            ("left", left_cache, ma), ("right", right_cache, mb)
        ):
            try:
                indexes[side] = load_bundles(cache, manifest)
            except ERRORS as error:
                report["errors"].append(
                    {"side": side, "artifact": str(cache), "error": str(error)}
                )

    def signature(data, path, requested):
        drv = data["drvs"][path]
        return (
            drv["name"],
            tuple(sorted(requested)),
            tuple(sorted(drv["outputs"])),
        )

    root_a, root_b = ma["root_drv"], mb["root_drv"]
    if signature(a, root_a, a["required"][root_a]) != signature(
        b, root_b, b["required"][root_b]
    ):
        report.update(
            status="invalid",
            configuration_differences=["root recipe/output names"],
        )
        return report, 1
    pairs, reverse = {root_a: root_b}, {root_b: root_a}
    bad, edges = {}, defaultdict(set)
    pending = [root_a]
    # Finish correspondence before comparing: shared edges can invalidate an
    # earlier candidate. A globally unique name alone never establishes a pair.
    for lp in pending:
        rp = pairs[lp]
        groups = []
        for data, parent in ((a, lp), (b, rp)):
            group = defaultdict(list)
            for dep, requested in data["inventory"][parent][
                "input_derivations"
            ].items():
                group[signature(data, dep, requested)].append(dep)
            groups.append(group)
        for key in sorted(groups[0].keys() | groups[1].keys()):
            ls, rs = sorted(groups[0][key]), sorted(groups[1][key])
            problem = None
            if len(ls) > 1 or len(rs) > 1:
                problem = "ambiguous"
            elif not ls or not rs:
                problem = "unmatched"
            else:
                ld, rd = ls[0], rs[0]
                if (ld in pairs and pairs[ld] != rd) or (
                    rd in reverse and reverse[rd] != ld
                ):
                    problem = "ambiguous"
                    for affected in (ld, reverse.get(rd)):
                        if affected in pairs:
                            bad[affected] = "ambiguous"
                else:
                    edges[lp].add(ld)
                    if ld not in pairs:
                        pairs[ld], reverse[rd] = rd, ld
                        pending.append(ld)
            if problem:
                bad[lp] = (
                    "ambiguous"
                    if problem == "ambiguous"
                    else bad.get(lp, "unmatched")
                )
                report["correspondence"].append(
                    {
                        "status": problem,
                        "parent_left": lp,
                        "parent_right": rp,
                        "recipe": key[0],
                        "requested_outputs": key[1],
                        "declared_outputs": key[2],
                        "left": ls,
                        "right": rs,
                    }
                )
    report["unpaired"] = {
        "left": sorted(a["drvs"].keys() - pairs.keys()),
        "right": sorted(b["drvs"].keys() - reverse.keys()),
    }

    visited, active = {}, set()

    def visit(lp):
        if lp in active:
            raise ValueError("cycle in rooted derivation graph")
        if lp in visited:
            return
        active.add(lp)
        for dep in sorted(edges[lp]):
            visit(dep)
        active.remove(lp)
        rp = pairs[lp]
        blocked = [
            dep
            for dep in sorted(edges[lp])
            if visited[dep] != "evidence-agrees"
        ]
        node = {
            "left": lp,
            "right": rp,
            "name": a["drvs"][lp]["name"],
            "correspondence": bad.get(lp, "rooted-unique"),
            "declared_outputs": sorted(a["drvs"][lp]["outputs"]),
            "requested_outputs": sorted(a["required"][lp] | b["required"][rp]),
            "dependencies": sorted(edges[lp]),
            "blocked_by": blocked,
            "normalized_inputs": "untested",
            "synthetic_identity": "untested",
            "source_boundaries": {
                "left": a["inventory"][lp]["input_sources"],
                "right": b["inventory"][rp]["input_sources"],
            },
            "source_comparison": "excluded",
            "outputs": {},
        }
        status = bad.get(lp, "blocked" if blocked else "evidence-agrees")
        if unsupported:
            node["synthetic_identity"] = (
                "unsupported" if cross_mode else "untested"
            )
            if status == "evidence-agrees":
                status = "unsupported"
        elif status == "evidence-agrees":
            node["source_errors"] = []
            for side, data, drv in (("left", a, lp), ("right", b, rp)):
                for source in data["inventory"][drv]["input_sources"]:
                    try:
                        actual(data, source)
                    except ERRORS as error:
                        node["source_errors"].append(
                            {"side": side, "path": source, "error": str(error)}
                        )
            for name in node["requested_outputs"]:
                if cross_mode and not all(
                    "hash" in data["drvs"][drv]["outputs"][name]
                    for data, drv in ((a, lp), (b, rp))
                ):
                    # Ordinary IA and rewritten CA NARs are distinct layers.
                    continue
                output = {"status": "equal"}
                for side, data, drv in (("left", a, lp), ("right", b, rp)):
                    try:
                        output[side] = output_evidence(
                            data, drv, name, cross_seed
                        )
                    except ERRORS as error:
                        output[side] = {"error": str(error)}
                        output["status"] = "missing"
                if output["status"] != "missing":
                    output["differences"] = [
                        k
                        for k in output["left"]["compared"]
                        if output["left"]["compared"][k]
                        != output["right"]["compared"][k]
                    ]
                    if output["differences"]:
                        output["status"] = "divergent"
                    if any(output[s]["boundary"] for s in ("left", "right")):
                        output["synthetic_comparison"] = (
                            "excluded-fixed-output-boundary"
                        )
                node["outputs"][name] = output
            states = {o["status"] for o in node["outputs"].values()}
            if "missing" in states or node["source_errors"]:
                status = "missing"
            elif "divergent" in states:
                status = "divergent"
        if claims and not unsupported and lp not in bad:
            boundaries = [
                all("hash" in data["drvs"][drv]["outputs"][name]
                    for name in node["requested_outputs"])
                for data, drv in ((a, lp), (b, rp))
            ]
            if all(boundaries):
                node["normalized_inputs"] = "excluded-fixed-output-boundary"
                node["synthetic_identity"] = "excluded-fixed-output-boundary"
            elif any(boundaries):
                node["normalized_inputs"] = "boundary-mismatch"
                if status == "evidence-agrees":
                    status = "divergent"
            else:
                evidence = node["signed_evidence"] = {}
                node["signed_outputs"] = {}
                for side, directory, data, drv in (
                    ("left", left, a, lp), ("right", right, b, rp)
                ):
                    try:
                        evidence[side] = signed_evidence(
                            directory, data, drv, indexes[side]
                        )
                    except ERRORS as error:
                        evidence[side] = {"error": str(error)}
                if any("error" in e for e in evidence.values()):
                    node["normalized_inputs"] = "missing"
                    node["synthetic_identity"] = "missing"
                    if not blocked:
                        status = "missing"
                else:
                    node["input_differences"] = [
                        k for k in ("resolved_input", "aterm")
                        if evidence["left"][k] != evidence["right"][k]
                    ]
                    node["normalized_inputs"] = (
                        "divergent" if node["input_differences"] else "equal"
                    )
                    for name in node["requested_outputs"]:
                        lo = evidence["left"]["outputs"][name]
                        ro = evidence["right"]["outputs"][name]
                        differences = [k for k in lo if lo[k] != ro[k]]
                        node["signed_outputs"][name] = {
                            "status": "divergent" if differences else "equal",
                            "differences": differences,
                        }
                    node["synthetic_identity"] = (
                        "divergent" if any(
                            o["differences"]
                            for o in node["signed_outputs"].values()
                        ) else "equal"
                    )
                    if status == "evidence-agrees" and "divergent" in (
                        node["normalized_inputs"], node["synthetic_identity"]
                    ):
                        status = "divergent"
                # Retain downstream diagnostics without attributing inherited
                # differences to a new local cause.
                node["attribution"] = "blocked" if blocked else "local"
        node["status"] = visited[lp] = status
        report["nodes"].append(node)

    try:
        visit(root_a)
    except ValueError as error:
        report["errors"].append({"artifact": "graph", "error": str(error)})
    report["counts"] = dict(Counter(n["status"] for n in report["nodes"]))
    failed = (
        report["errors"]
        or report["correspondence"]
        or any(report["unpaired"].values())
        or any(
            n["status"] in {"missing", "divergent", "ambiguous", "unmatched"}
            for n in report["nodes"]
        )
    )
    report["status"] = (
        "failed"
        if failed
        else "unsupported" if unsupported
        else "diagnostic-agreement" if claims else "baseline-agreement"
    )
    return report, 1 if failed else 2 if unsupported else 0


def write_preimages(report, directory):
    for node in report["nodes"]:
        evidence = node.get("signed_evidence", {})
        if not any("aterm" in e for e in evidence.values()):
            continue
        pair = (node["left"] + "\0" + node["right"]).encode()
        destination = (
            directory / "preimages" / hashlib.sha256(pair).hexdigest()
        )
        destination.mkdir(parents=True, exist_ok=True)
        artifacts = node["preimage_artifacts"] = {}
        for side, item in evidence.items():
            if "aterm" in item:
                path = destination / (side + ".aterm")
                path.write_bytes(item["aterm"].encode("utf-8"))
                artifacts[side] = str(path)
        if "aterm" not in node.get("input_differences", []):
            continue
        try:
            result = subprocess.run(
                ["difft", "--color=never", "--display=inline",
                 "--override=*:Python", artifacts["left"], artifacts["right"]],
                capture_output=True, check=False,
            )
            diff = destination / "structural.diff"
            diff.write_bytes(result.stdout)
            (destination / "difft.stderr").write_bytes(result.stderr)
            artifacts.update(
                diff=str(diff), difft_exit_status=result.returncode
            )
            if result.returncode != 0:
                raise ValueError(f"difft failed with exit {result.returncode}")
        except (OSError, ValueError) as error:
            report["errors"].append(
                {"artifact": str(destination), "error": str(error)}
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("left", "right", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("left-cache", "right-cache"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    report, code = compare(
        args.left, args.right, args.left_cache, args.right_cache
    )
    args.output.mkdir(parents=True, exist_ok=True)
    write_preimages(report, args.output)
    if report["errors"]:
        report["status"], code = "failed", 1
    destination = args.output / "report.json"
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"{report['status']}: {report['scope'] or 'no comparison'}; "
        f"{len(report['nodes'])} paired nodes; "
        f"{len(report['errors'])} collection/schema errors"
    )
    if report.get("counts"):
        print(
            ", ".join(f"{k}={v}" for k, v in sorted(report["counts"].items()))
        )
    for node in report["nodes"]:
        if node["status"] != "evidence-agrees":
            print(f"  {node['status']}: {node['name']} ({node['left']})")
            if node.get("input_differences"):
                print("    inputs: " + ", ".join(node["input_differences"]))
            for name, output in node["outputs"].items():
                if output["status"] == "divergent":
                    print(f"    {name}: " + ", ".join(output["differences"]))
            for name, output in node.get("signed_outputs", {}).items():
                if output["differences"]:
                    print(f"    signed {name}: "
                          + ", ".join(output["differences"]))
    if "unsupported" in report:
        print(report["unsupported"])
    if "configuration_differences" in report:
        print(
            "Invalid controls: "
            + ", ".join(report["configuration_differences"])
        )
    if "invalid_reason" in report:
        print(report["invalid_reason"])
    print(
        "Full equivalence and signature authentication are NOT established. "
        f"Report: {destination}"
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
