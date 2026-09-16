#!/usr/bin/env python3
"""Inspect JSON Lines bundles without authenticating them; never a verifier."""

import argparse
import base64
from collections import defaultdict
import hashlib
import json
from pathlib import Path


def decode_json(encoded):
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def process_json_files(input_dir, output_dir, key_field="drv_path", allow_duplicate_keys=False, debug=False):
    groups = defaultdict(lambda: defaultdict(list))
    count = 0
    for path in sorted(Path(input_dir).iterdir()):
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            bundle = json.loads(line)
            envelope = bundle["dsseEnvelope"]
            statement = decode_json(envelope["payload"])
            predicate = statement["predicate"]
            hint = bundle["verificationMaterial"]["publicKey"]["hint"]
            if key_field == "in":
                key = predicate["buildDefinition"]["externalParameters"]["resolvedInputHash"]
            else:
                byproduct = next(v for v in predicate["runDetails"].get("byproducts", [])
                                 if v["name"] == "laut-debug-preimage")
                metadata = decode_json(byproduct["content"])
                key = metadata["drv_name" if key_field == "drv_name" else "rdrv_path"]
            if groups[hint][key] and not allow_duplicate_keys:
                raise ValueError(f"multiple claims for {key!r}; use --allow-duplicate-keys")
            groups[hint][key].append(statement)
            count += 1
            if debug:
                print(f"{path.name}: unauthenticated hint {hint!r}, {key}")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    for hint, records in groups.items():
        # Hints are untrusted strings, not filenames or signer authorities.
        name = hashlib.sha256(hint.encode()).hexdigest()
        data = dict(records) if allow_duplicate_keys else {k: v[0] for k, v in records.items()}
        (output / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")
    print(f"Extracted {count} statements grouped by {len(groups)} unauthenticated hints")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--key-field", choices=["drv_path", "in", "drv_name"], default="drv_path")
    parser.add_argument("--allow-duplicate-keys", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    process_json_files(args.input_dir, args.output_dir, args.key_field, args.allow_duplicate_keys, args.debug)


if __name__ == "__main__":
    main()
