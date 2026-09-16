"""Tamper with *every* signature in one trace's signed preimage.

Appends `marker` to each bundle's signed debugging byproduct
so the verifier's debug probe sees corpus entries that differ from what
the verifier computes locally.

Usage: tamper-preimage <trace-dir> <marker>

Both signers' signatures must be tampered: the orchestrator only fires
the probe when the post-verify signature list is empty, so leaving any
valid signature behind means the probe never runs.

We don't re-sign — the corpus builder is permissive (parses the DSSE
payload without verifying), and the regular verify path rejects the
broken signatures, causing a miss and firing the probe.
"""

import base64
import json
import os
import sys


def tamper_bundle(bundle, marker):
    payload_b64 = bundle["dsseEnvelope"]["payload"]
    padding = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    descriptor = next(v for v in payload["predicate"]["runDetails"]["byproducts"]
                      if v["name"] == "laut-debug-preimage")
    debug = json.loads(base64.b64decode(descriptor["content"]))
    debug["rdrv_aterm_ca_preimage"] = (
        debug["rdrv_aterm_ca_preimage"] + " " + marker
    )
    descriptor["content"] = base64.b64encode(json.dumps(debug).encode()).decode()
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode()
    return bundle, debug.get("drv_name")


def main(trace_dir, marker):
    victim_name = sorted(os.listdir(trace_dir))[0]
    victim_path = os.path.join(trace_dir, victim_name)
    with open(victim_path) as f:
        body = [json.loads(line) for line in f if line.strip()]
    tampered = [tamper_bundle(bundle, marker) for bundle in body]
    drv_name = tampered[0][1] if tampered else None
    with open(victim_path, "w") as f:
        for bundle, _ in tampered:
            f.write(json.dumps(bundle, separators=(",", ":")) + "\n")
    # Stdout doubles as a smoke check for the test driver.
    print("victim_drv_name", drv_name)
    print("victim_hash", victim_name)
    print("tampered_signature_count", len(tampered))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
