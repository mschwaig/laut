"""Re-add prefetched FODs inside the experiment VM, before eval/build/begin.

Package as laut-seed-inputs with Python 3 and the patched Nix on PATH. The
sources manifest lists {path, ca: {method, hash}} descriptors for canonical
outputs preloaded via additionalPaths, using their declared mode and SRI hash.
The output is {original: {seeded, ca, narHash, narSize}}; hashes retain Nix's
JSON representation. The sign script can copy it into the experiment state.

This does not build derivations or create Nix's build-time unseeded records.
NixOS store registration may discard ca; canonical path binding and unchanged
NAR identity verify the re-add without registered ca. Run only in the VM.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


STORE_NAME = re.compile(r"[0-9abcdfghijklmnpqrsvwxyz]{32}-(.+)")


def nix(*args):
    return subprocess.run(
        ["nix", "--store", "local", *args],
        check=True, capture_output=True, text=True,
    ).stdout.removesuffix("\n")


def path_info(path):
    data = json.loads(nix("path-info", "--json", "--json-format", "2", path))
    p = Path(path)
    if (not isinstance(data, dict) or data.get("version") != 2
            or data.get("storeDir") != str(p.parent)
            or not isinstance(data.get("info"), dict)
            or set(data["info"]) != {p.name}):
        raise ValueError(f"{path}: unexpected path-info format-2 envelope")
    info = data["info"][p.name]
    if not isinstance(info, dict):
        raise ValueError(f"{path}: missing path metadata")
    if info.get("references") != []:
        raise ValueError(f"{path}: references must be present and empty")
    if (not isinstance(info.get("narHash"), str) or not info["narHash"]
            or type(info.get("narSize")) is not int or info["narSize"] < 0):
        raise ValueError(f"{path}: missing or invalid NAR metadata")
    return info


def seed_inputs(sources, output, seed=None):
    descriptors = json.loads(sources.read_text())
    if not isinstance(descriptors, list):
        raise ValueError("sources must be a JSON list of descriptors")
    declarations = {}
    for descriptor in descriptors:
        if (not isinstance(descriptor, dict)
                or not isinstance(descriptor.get("path"), str)
                or not Path(descriptor["path"]).is_absolute()
                or not STORE_NAME.fullmatch(Path(descriptor["path"]).name)):
            raise ValueError("each descriptor requires an absolute store path")
        path, ca = descriptor["path"], descriptor.get("ca")
        if not isinstance(ca, dict) or ca.get("method") not in ("flat", "nar"):
            raise ValueError(
                f"{path}: requires a fixed flat/nar content address")
        if (not isinstance(ca.get("hash"), str) or not re.fullmatch(
                r"[a-z0-9]+-[A-Za-z0-9+/]+={0,2}", ca["hash"])):
            raise ValueError(f"{path}: expected an SRI content hash")
        if path in declarations and declarations[path] != ca:
            raise ValueError(
                f"{path}: conflicting content address declarations")
        declarations[path] = ca

    configured_seed = nix("config", "show", "store-path-seed")
    if seed is not None and seed != configured_seed:
        raise ValueError(
            f"configured seed {configured_seed!r} != expected {seed!r}")

    # Check all input references and NAR metadata before mutating the store.
    originals = {p: path_info(p) for p in declarations}
    mapping = {}
    for original, info in originals.items():
        ca = declarations[original]
        name = Path(original).name[33:]
        args = ("store", "add", "--mode", ca["method"],
                "--hash-algo", ca["hash"].split("-", 1)[0], "--name", name)
        canonical = nix("--store-path-seed", "", *args, "--dry-run", original)
        if canonical != original:
            raise ValueError(
                f"{original}: canonical dry-run path "
                f"{canonical!r} != original")
        expected = nix(*args, "--dry-run", original)
        if (Path(expected).parent != Path(original).parent
                or not STORE_NAME.fullmatch(Path(expected).name)
                or Path(expected).name[33:] != name):
            raise ValueError(
                f"{original}: invalid dry-run store path {expected!r}")
        if configured_seed == "" and expected != original:
            raise ValueError(
                f"{original}: empty seed must preserve path identity, "
                f"got {expected}")
        actual = nix(*args, original)
        if actual != expected:
            raise ValueError(
                f"{original}: added path {actual!r} != dry-run {expected!r}")
        added = path_info(actual)
        if any(added[key] != info[key] for key in ("narHash", "narSize")):
            raise ValueError(f"{original}: NAR metadata changed after re-add")
        mapping[original] = {"seeded": actual, "ca": ca, **{
            key: added[key] for key in ("narHash", "narSize")}}

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(mapping, indent=2, sort_keys=True) + "\n")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="laut-seed-inputs", description=__doc__)
    parser.add_argument("--sources", type=Path,
                        default=Path("/etc/laut-prefetched-sources.json"))
    parser.add_argument("--output", type=Path,
                        default=Path("/var/lib/laut-seeded-inputs.json"))
    parser.add_argument(
        "--seed", help="expected configured seed (not an override)")
    args = parser.parse_args(argv)
    try:
        seed_inputs(args.sources, args.output, args.seed)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        detail = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            detail = error.stderr
        print(f"laut-seed-inputs: {detail.strip()}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
