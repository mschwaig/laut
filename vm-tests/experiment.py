"""Observational VM artifacts, not verification or an equivalence test.

CLI (one experiment/build at a time in each VM):
  laut-experiment begin ROOT_DRV
  laut-experiment record --sign-status "$status"  # DRV_PATH / OUT_PATHS
  laut-experiment collect

Requires Python's stdlib and Nix 2.35's `nix` on PATH, with nix-command and
ca-derivations enabled. No daemon queries: local-store metadata includes the
experimental unseeded fields. Run as the builder's privileged hook user.
Begin must precede the build; collect must follow all hooks, before any GC.
Newly valid required outputs need hook records; preloaded outputs do not.
The full raw recipe inventory is retained, but required evidence stops at FODs;
their recipe inputs are excluded unless reached through an ordinary branch.
Export the entire state directory, including failed/incomplete sidecars.
The contents cache is STATE/HOSTNAME/contents. Only the public key is read.
No config/key directories, environment dumps, hashes, or trust rules are added.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import uuid


STORE = "/nix/store/"
BASE = r"[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+"
ERRORS = (OSError, ValueError, RuntimeError, KeyError, TypeError)


def store_path(value, basename=False):
    if not isinstance(value, str):
        raise ValueError("store path is not a string")
    name = value if basename else value.removeprefix(STORE)
    if not re.fullmatch(BASE, name) or (
            not basename and value != STORE + name):
        raise ValueError(f"invalid store path: {value!r}")
    return STORE + name


def write_json(path, value):
    # A reader can distinguish an interrupted operation from a finished one.
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def read_json(path):
    return json.loads(path.read_bytes())


def run(args, destination):
    """Save exact stdout and a command sidecar, including on failure."""
    command = ["nix", "--store", "local", *args]
    sidecar = destination.with_name(destination.name + ".status.json")
    try:
        result = subprocess.run(command, capture_output=True, check=False)
    except OSError as error:
        write_json(sidecar, {"status": "error", "command": command,
                             "error": str(error)})
        raise
    destination.write_bytes(result.stdout)
    write_json(sidecar, {
        "status": "complete" if result.returncode == 0 else "error",
        "command": command, "exit_status": result.returncode,
        "stderr": result.stderr.decode("utf-8", errors="replace")})
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}: {command!r}")
    return result.stdout


def attempt(report, label, action, required=True):
    try:
        return action()
    except ERRORS as error:
        report["errors"].append({"artifact": label, "required": required,
                                 "error": str(error)})
        return None


def finish(path, report):
    incomplete = any(e["required"] for e in report["errors"])
    report["status"] = "incomplete" if incomplete else "complete"
    write_json(path, report)
    return 1 if report["status"] != "complete" else 0


def derivations(raw):
    data = json.loads(raw)
    if data["version"] != 4 or not data["derivations"]:
        raise ValueError("expected nonempty v4 derivations")
    result = {}
    for name, drv in data["derivations"].items():
        path = store_path(name, basename=True)
        if drv["version"] != 4 or not path.endswith(".drv"):
            raise ValueError("expected v4 derivation")
        inputs = drv["inputs"]
        for dependency, node in inputs["drvs"].items():
            store_path(dependency, basename=True)
            if node.get("dynamicOutputs"):
                raise ValueError("dynamic derivation inputs are unsupported")
        for source in inputs["srcs"]:
            store_path(source, basename=True)
        if not drv["outputs"]:
            raise ValueError("derivation has no outputs")
        result[path] = drv
    return result


def aterm_outputs(raw):
    # Only parse the output tuples. Never reserialize the stored derivation or
    # derive a FOD path from its hash (that loses store-path seeding).
    text = raw.decode("utf-8")
    if not text.startswith("Derive(["):
        raise ValueError("invalid ATerm header")
    position = len("Derive([")
    quoted = r'"(?:[^"\\]|\\.)*"'
    output = re.compile(r"\(" + ",".join([f"({quoted})"] * 4) + r"\)")
    outputs = {}
    while True:
        match = output.match(text, position)
        if not match:
            raise ValueError("invalid ATerm output tuple")
        name, path, _, _ = [json.loads(part) for part in match.groups()]
        if name in outputs:
            raise ValueError("duplicate ATerm output")
        outputs[name] = store_path(path) if path else None
        position = match.end()
        if text[position:position + 2] == "],":
            return outputs
        if text[position:position + 1] != ",":
            raise ValueError("invalid ATerm output separator")
        position += 1


def path_info(raw):
    data = json.loads(raw)
    if data["version"] != 2 or data["storeDir"] != STORE.rstrip("/"):
        raise ValueError("expected local /nix/store path-info v2")
    result = {}
    for name, info in data["info"].items():
        path = store_path(name, basename=True)
        if info is not None:
            if info["version"] != 2 or info["storeDir"] != data["storeDir"]:
                raise ValueError("invalid path-info entry")
            for reference in info["references"]:
                store_path(reference, basename=True)
            if not info["narHash"] or not isinstance(info["narSize"], int):
                raise ValueError("missing NAR metadata")
        result[path] = info
    return result


def snapshot(paths, destination):
    args = ["path-info", "--json", "--json-format", "2"]
    info = path_info(run([*args, *paths], destination))
    if not info or any(value is None for value in info.values()):
        raise ValueError("missing or invalid path metadata")
    return info


def inventory_entry(path, drv, raw):
    outputs = aterm_outputs(raw)
    if outputs.keys() != drv["outputs"].keys():
        raise ValueError("JSON/ATerm output names differ")
    for name, output in drv["outputs"].items():
        if "path" in output and store_path(
                output["path"], True) != outputs[name]:
            raise ValueError("JSON/ATerm output paths differ")
    return {
        "drv_path": path, "outputs": outputs,
        "input_sources": [store_path(p, True) for p in drv["inputs"]["srcs"]],
        "input_derivations": {store_path(p, True): node["outputs"]
                              for p, node in drv["inputs"]["drvs"].items()}}


def fixed_output(drv):
    return all("hash" in output for output in drv["outputs"].values())


def required_graph(drvs, root):
    """Requested outputs in the rooted graph, with FOD recipes as terminals."""
    required = {root: set(drvs[root]["outputs"])}
    pending = [root]
    for path in pending:
        drv = drvs[path]
        if fixed_output(drv):
            continue
        for name, node in drv["inputs"]["drvs"].items():
            dependency = store_path(name, True)
            if dependency not in required:
                required[dependency] = set()
                pending.append(dependency)
            required[dependency].update(node["outputs"])
    return required


def begin(args, report):
    root_drv = store_path(args.root_drv)
    if not root_drv.endswith(".drv"):
        raise ValueError("ROOT_DRV must be a derivation")
    manifest = read_json(args.manifest)
    for field in ("id", "addressing", "seed", "target", "system", "nixPackage",
                  "nixRevision", "laut-sign-only"):
        if not isinstance(manifest[field], str):
            raise ValueError(f"manifest {field} must be a string")
    for field in ("source", "revision"):
        if not isinstance(manifest["nixpkgs"][field], str):
            raise ValueError(f"manifest nixpkgs.{field} must be a string")
    hostname = socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", hostname):
        raise ValueError("unsafe hostname")
    public_key = args.public_key.read_text().strip()
    key_name, encoded = public_key.split(":")
    if not key_name or len(base64.b64decode(encoded, validate=True)) != 32:
        raise ValueError("expected an ed25519 public key, never a private key")
    manifest.update(
        schema_version=1,
        run_id=str(uuid.uuid4()),
        hostname=hostname,
        root_drv=root_drv,
        public_key=public_key)
    write_json(args.state / "manifest.json", manifest)
    raw = run(["derivation", "show", "--recursive", root_drv],
              args.state / "derivations.json")
    drvs = derivations(raw)
    if root_drv not in drvs:
        raise ValueError("root absent from recursive derivations")
    aterms = args.state / "aterms"
    aterms.mkdir()
    inventory = {}
    for path, drv in drvs.items():
        entry = attempt(report, path, lambda: inventory_entry(
            path, drv, run(["store", "cat", path], aterms / Path(path).name)))
        if entry is not None:
            inventory[path] = entry
    write_json(args.state / "inventory.json", inventory)
    # --all is essential: future CA paths are not known yet, but can already
    # exist (e.g. substituted FODs). Do not mistake them for observed builds.
    raw = run(["path-info", "--all", "--json", "--json-format", "2"],
              args.state / "prebuild-path-info.json")
    prebuild = path_info(raw)
    write_json(args.state / "prebuild-valid-paths.json",
               sorted(path for path, info in prebuild.items()
                      if info is not None))


def record(args, report, directory):
    report.update(sign_exit_status=args.sign_status,
                  drv_path=os.environ.get("DRV_PATH"),
                  out_paths=os.environ.get("OUT_PATHS", "").split())
    for failure in args.optional_failure:
        report["errors"].append({"artifact": "hook", "required": False,
                                 "error": failure})
    write_json(directory / "status.json", report)
    if read_json(args.state / "begin.json")["status"] != "complete":
        raise ValueError("begin is not complete")
    drv_path = store_path(report["drv_path"])
    paths = [store_path(path) for path in report["out_paths"]]
    if not paths or not drv_path.endswith(".drv"):
        raise ValueError("DRV_PATH and nonempty OUT_PATHS are required")

    def capture_derivation():
        drvs = derivations(run(["derivation", "show", drv_path],
                               directory / "derivation.json"))
        if set(drvs) != {drv_path}:
            raise ValueError("hook derivation missing from JSON")
        return drvs[drv_path]

    drv = attempt(report, "derivation", capture_derivation)
    raw = attempt(report, "aterm", lambda: run(
        ["store", "cat", drv_path], directory / "derivation.aterm"))
    if drv is not None and raw is not None:
        entry = attempt(report, "inventory",
                        lambda: inventory_entry(drv_path, drv, raw))
        if entry is not None:
            write_json(directory / "inventory.json", entry)

    def capture_outputs():
        info = snapshot(paths, directory / "output-path-info.json")
        if set(info) != set(paths):
            raise ValueError(
                "output snapshot does not cover OUT_PATHS exactly")

    attempt(report, "output-path-info", capture_outputs)


def collect(args, report):
    state = args.state
    if read_json(state / "begin.json")["status"] != "complete":
        raise ValueError("begin is not complete")
    manifest = read_json(state / "manifest.json")
    inventory = read_json(state / "inventory.json")
    if not inventory or manifest["root_drv"] not in inventory:
        raise ValueError("missing root inventory")
    drvs = derivations((state / "derivations.json").read_bytes())
    if drvs.keys() != inventory.keys():
        raise ValueError("incomplete original derivation inventory")
    for path, drv in drvs.items():
        def check_original():
            raw = (state / "aterms" / Path(path).name).read_bytes()
            if inventory_entry(path, drv, raw) != inventory[path]:
                raise ValueError(
                    "original inventory differs from raw artifacts")
        attempt(report, f"original:{path}", check_original)
    prebuild = set(read_json(state / "prebuild-valid-paths.json"))
    prebuild_info = path_info((state / "prebuild-path-info.json").read_bytes())
    if prebuild != {path for path, info in prebuild_info.items()
                    if info is not None}:
        raise ValueError("prebuild validity differs from raw snapshot")
    candidates = {}

    def add(path, role, required=True, observation=None):
        store_path(path)
        item = candidates.setdefault(path, {
            "roles": [], "required": False, "hook_invocations": [],
            "prebuild_valid": path in prebuild})
        if role not in item["roles"]:
            item["roles"].append(role)
        item["required"] |= required
        if observation and observation not in item["hook_invocations"]:
            item["hook_invocations"].append(observation)

    required_outputs = required_graph(drvs, manifest["root_drv"])
    report.update(
        fixed_output_boundaries=sorted(
            path for path in required_outputs if fixed_output(drvs[path])),
        excluded_recipe_derivations=sorted(
            drvs.keys() - required_outputs.keys()))
    entries = [inventory[path] for path in required_outputs]
    boundaries = set(report["fixed_output_boundaries"])
    excluded_recipes = set(report["excluded_recipe_derivations"])
    for directory in sorted((state / "observations").glob("*")):
        def load_observation():
            observation = read_json(directory / "status.json")
            if observation["status"] != "complete":
                raise ValueError("incomplete hook observation")
            entry = read_json(directory / "inventory.json")
            drv_path = observation["drv_path"]
            drvs = derivations((directory / "derivation.json").read_bytes())
            raw = (directory / "derivation.aterm").read_bytes()
            if set(drvs) != {drv_path} or inventory_entry(
                    drv_path, drvs[drv_path], raw) != entry:
                raise ValueError("hook inventory differs from raw artifacts")
            entries.append(entry)
            if fixed_output(drvs[drv_path]):
                boundaries.add(drv_path)
            info = path_info(
                (directory / "output-path-info.json").read_bytes())
            if not info or set(info) != set(observation["out_paths"]):
                raise ValueError("missing hook output snapshot")
            for path, value in info.items():
                if value is None:
                    raise ValueError("invalid hook output snapshot")
                add(path, "hook-output", observation=directory.name)
        attempt(report, f"observation:{directory.name}", load_observation)

    for entry in entries:
        # Hooks preserve outputs but cannot reopen excluded original recipes.
        # Unknown hooks may be resolved CA drvs; keep their input handling.
        if (entry["drv_path"] not in boundaries
                and entry["drv_path"] not in excluded_recipes):
            for path in entry["input_sources"]:
                add(path, "input-source")
            for dependency, names in entry["input_derivations"].items():
                required_outputs.setdefault(dependency, set()).update(names)
        for name, path in entry["outputs"].items():
            if path:
                add(path, "declared-output", required=False)

    resolutions = state / "resolutions"
    resolutions.mkdir(exist_ok=True)
    root_outputs = set()
    unresolved = []
    output_paths = {}
    by_path = {**inventory, **{entry["drv_path"]: entry for entry in entries}}
    for drv_path, names in sorted(required_outputs.items()):
        for name in sorted(names):
            label = f"{drv_path}^{name}"
            entry = by_path.get(drv_path)
            if entry is None or name not in entry["outputs"]:
                report["errors"].append({
                    "artifact": label, "required": True,
                    "error": "missing derivation/output inventory"})
                unresolved.append(label)
                continue
            path = entry["outputs"][name]
            paths = [path] if path else None
            if paths is None:
                # Ask Nix for its registered realization. A hook's resolved
                # drv is NOT identified with an unresolved drv by name/hash.
                resolved = attempt(report, label, lambda: snapshot(
                    [label], resolutions / (str(uuid.uuid4()) + ".json")))
                if resolved is not None and len(resolved) == 1:
                    paths = list(resolved)
                else:
                    unresolved.append(label)
                    if resolved is not None:
                        report["errors"].append({
                            "artifact": label, "required": True,
                            "error": "expected one realized output"})
                    continue
            for path in paths:
                output_paths[label] = path
                role = ("root-output" if drv_path == manifest["root_drv"]
                        else "build-input-output")
                add(path, role)
                if role == "root-output":
                    root_outputs.add(path)

    metadata = state / "path-info"
    metadata.mkdir(exist_ok=True)
    realized = {}
    pending = sorted(candidates)
    for path in pending:
        item = candidates[path]

        def query():
            info = path_info(run(
                ["path-info", "--json", "--json-format", "2", path],
                metadata / (Path(path).name + ".json")))
            if set(info) != {path} or info[path] is None:
                raise ValueError("path is not valid at collection")
            return info[path]

        info = attempt(report, path, query, required=item["required"])
        item["collection_status"] = "missing" if info is None else "valid"
        if info is not None:
            realized[path] = info
            for reference in info["references"]:
                reference = store_path(reference, True)
                if reference not in candidates:
                    pending.append(reference)
                add(reference, "registered-reference")
    # A previously queried optional output may later become a required ref.
    for path, item in candidates.items():
        if item["required"] and path not in realized:
            report["errors"].append({
                "artifact": path, "required": True,
                "error": "missing required realized path"})
        if (item["required"] and path in realized
                and not item["prebuild_valid"]
                and not item["hook_invocations"]
                and {"root-output", "build-input-output"}.intersection(
                    item["roles"])):
            report["errors"].append({
                "artifact": path, "required": True,
                "error": "newly valid output has no hook observation"})
    root_outputs.intersection_update(realized)
    report.update(root_outputs=sorted(root_outputs),
                  unresolved_outputs=unresolved,
                  output_paths=output_paths,
                  realized_path_count=len(realized))
    write_json(state / "paths.json", candidates)
    write_json(state / "realized-path-info.json", realized)
    if not root_outputs or not realized:
        report["errors"].append({"artifact": "root-outputs", "required": True,
                                 "error": "no realized root outputs"})
    if not realized:
        return
    cache = state / manifest["hostname"] / "contents"
    cache.mkdir(parents=True, exist_ok=True)
    report["contents_cache"] = cache.resolve().as_uri()
    # Copy even partial collections for diagnostics, but never report success
    # when required evidence is missing. Batch to avoid exec argument limits.
    paths = sorted(realized)
    for index in range(0, len(paths), 128):
        attempt(report, f"contents:{index}", lambda: run(
            ["copy", "--no-check-sigs", "--to", report["contents_cache"],
             *paths[index:index + 128]], state / f"copy-{index}.stdout"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state",
        type=Path,
        default=Path("/var/lib/laut-experiment"))
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("begin")
    start.add_argument("root_drv")
    start.add_argument(
        "--manifest",
        type=Path,
        default=Path("/etc/laut-experiment.json"))
    start.add_argument(
        "--public-key",
        type=Path,
        default=Path("/etc/nix/public-key"))
    hook = sub.add_parser("record")
    hook.add_argument("--sign-status", type=int, required=True)
    hook.add_argument("--optional-failure", action="append", default=[])
    sub.add_parser("collect")
    args = parser.parse_args(argv)
    args.state.mkdir(parents=True, exist_ok=True)
    report = {"status": "incomplete", "errors": []}
    if args.command == "record":
        invocation = str(uuid.uuid4())
        directory = args.state / "observations" / invocation
        directory.mkdir(parents=True)
        report["invocation"] = invocation
        status = directory / "status.json"
    else:
        status = args.state / (args.command + ".json")
        if args.command == "begin" and status.exists():
            parser.error(
                "begin already attempted; use a fresh state directory")

    def action():
        if args.command == "record":
            record(args, report, directory)
        elif args.command == "begin":
            begin(args, report)
        else:
            collect(args, report)

    write_json(status, report)
    attempt(report, args.command, action)
    code = finish(status, report)
    if code:
        print(f"{args.command} incomplete; see {status}", file=sys.stderr)
        for error in report["errors"]:
            print(f"  {error['artifact']}: {error['error']}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
