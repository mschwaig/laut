"""Compare tiny native CA outputs with the existing synthetic hashing helpers.

The independent hash check covers Nix's HashModuloSink preimage, not a second
implementation of synthetic paths or castore. Run only inside the oracle VM.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess


CASES = {
    "plain": 0,
    "self-once": 1,
    "self-twice": 2,
    "zero-and-self": 1,
    "chunked": 2,
    "symlink": 1,
    "dependency": 0,
}


def analyze(path, nar, info, probe, expected_self_refs):
    self_hash = Path(path).name[:32].encode("ascii")
    positions = []
    offset = 0
    while (offset := nar.find(self_hash, offset)) != -1:
        positions.append(offset)
        offset += len(self_hash)
    masked = nar.replace(self_hash, bytes(len(self_hash)))
    modulo = hashlib.sha256(masked)
    for offset in positions:
        modulo.update(f"|{offset}".encode("ascii"))
    expected_ca = "sha256-" + base64.b64encode(modulo.digest()).decode()
    nar_hash = hashlib.sha256(nar).digest()
    return {
        "self_positions": positions,
        "masked_nar_sha256": hashlib.sha256(masked).hexdigest(),
        "expected_ca": expected_ca,
        "checks": {
            "self_reference_count": len(positions) == expected_self_refs,
            "native_nar_metadata": info["narHash"] == (
                "sha256-" + base64.b64encode(nar_hash).decode()
            ) and info["narSize"] == len(nar),
            "native_ca_with_positions": info["ca"] == {
                "method": "nar", "hash": expected_ca,
            },
            "synthetic_path": probe["path"] == path,
            "rewritten_nar_hash": probe["nar_hash"] == nar_hash.hex(),
            "rewritten_nar_size": probe["nar_size"] == len(nar),
            "rewritten_castore": (
                probe["castore_entry"] == probe["native_castore_entry"]
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {
        "configuration": json.loads(Path("/etc/ca-oracle.json").read_text()),
        "cases": {}, "checks": {}, "errors": [],
    }
    for case, count in CASES.items():
        directory = args.output / case
        directory.mkdir()

        def run(label, *command):
            result = subprocess.run(command, capture_output=True, check=False)
            (directory / label).write_bytes(result.stdout)
            (directory / (label + ".stderr")).write_bytes(result.stderr)
            (directory / (label + ".command.json")).write_text(json.dumps({
                "command": command, "exit_status": result.returncode,
            }))
            if result.returncode:
                raise ValueError(f"{case}/{label}: exit {result.returncode}")
            return result.stdout

        try:
            expr = ["/etc/ca-oracle.nix", "--argstr", "case", case]
            drv = run("drv", "nix-instantiate", *expr).decode().strip()
            path = run(
                "output", "nix-build", *expr,
                "--no-out-link", "--no-substitute",
            ).decode().strip()
            run("original.aterm", "nix", "store", "cat", drv)
            metadata = json.loads(run(
                "path-info.json", "nix", "--store", "local", "path-info",
                "--json", "--json-format", "2", path,
            ))
            if (metadata["version"] != 2
                    or metadata["storeDir"] != "/nix/store"):
                raise ValueError("expected /nix/store path-info v2")
            info = metadata["info"][Path(path).name]
            references = ["/nix/store/" + p for p in info["references"]]
            external = [p for p in references if p != path]
            probe = json.loads(run(
                "probe.json", "ca_identity_probe", path, *external
            ))
            nar = run("output.nar", "nix-store", "--dump", path)
            result = analyze(path, nar, info, probe, count)
            result.update(path=path, drv=drv, metadata=info, probe=probe)
            result["checks"]["registered_self_reference"] = (
                (path in references) == bool(count)
            )
            result["checks"]["external_reference_count"] = (
                len(external) == (1 if case == "dependency" else 0)
            )
            report["cases"][case] = result
        except (OSError, ValueError, KeyError, TypeError) as error:
            report["errors"].append(str(error))
    if {"self-twice", "zero-and-self"} <= report["cases"].keys():
        full = report["cases"]["self-twice"]
        zeroed = report["cases"]["zero-and-self"]
        report["checks"] = {
            "collision_fixture_same_masked_nar": (
                full["masked_nar_sha256"] == zeroed["masked_nar_sha256"]
            ),
            "positions_distinguish_zeroed_reference": (
                full["metadata"]["ca"] != zeroed["metadata"]["ca"]
            ),
        }
    passed = (
        not report["errors"]
        and report["cases"].keys() == CASES.keys()
        and all(report["checks"].values())
        and all(all(c["checks"].values()) for c in report["cases"].values())
    )
    report["status"] = "agreement" if passed else "failed"
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
