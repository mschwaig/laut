"""Offline, unauthenticated baseline evidence, never a laut equivalence test.

Run: python3 vm-tests/compare-experiments.py \
    --left STATE --right STATE --output DIR
Writes DIR/report.json. Exit 0 means only the selected metadata checks agree;
1 means invalid, missing, ambiguous or divergent evidence; 2 means unsupported.
No contents, signatures, ATerms or synthetic identities are computed/verified.
Source inputs are excluded from comparison; normalized identities are untested.
Manifests must have schema_version=1 and a nonempty run_id. Known
self-comparisons are rejected; distinct IDs do not prove independent builds.
"""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

from experiment import derivations, read_json, store_path


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


def compare(left, right):
    report = {
        "version": 1,
        "status": "missing",
        "scope": None,
        "equivalence": "untested",
        "authenticated": False,
        "directories": {"left": str(left), "right": str(right)},
        "errors": [],
        "collection": {},
        "correspondence": [],
        "nodes": [],
    }
    a, b = load(left, "left", report), load(right, "right", report)
    if a is None or b is None:
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
    unsupported = cross_mode or (
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
        else "unsupported" if unsupported else "baseline-agreement"
    )
    return report, 1 if failed else 2 if unsupported else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("left", "right", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    report, code = compare(args.left, args.right)
    args.output.mkdir(parents=True, exist_ok=True)
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
            for name, output in node["outputs"].items():
                if output["status"] == "divergent":
                    print(f"    {name}: " + ", ".join(output["differences"]))
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
        "Normalized inputs and synthetic equivalence are NOT established. "
        f"Report: {destination}"
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
