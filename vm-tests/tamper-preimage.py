"""Tamper with *every* signature in one trace's signed preimage.

Appends `marker` to each JWS payload's `in.debug.rdrv_aterm_ca_preimage`
so the verifier's debug probe sees corpus entries that differ from what
the verifier computes locally.

Usage: tamper-preimage <trace-dir> <marker>

Both signers' signatures must be tampered: the orchestrator only fires
the probe when the post-verify signature list is empty, so leaving any
valid signature behind means the probe never runs.

We don't re-sign — the corpus builder is permissive (parses the JWS
payload without verifying), and the regular verify path rejects the
broken signatures, causing a miss and firing the probe.
"""

import base64
import json
import os
import sys


def tamper_jws(jws, marker):
    header_b64, payload_b64, sig_b64 = jws.split(".")
    padding = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    debug = payload["in"]["debug"]
    debug["rdrv_aterm_ca_preimage"] = (
        debug["rdrv_aterm_ca_preimage"] + " " + marker
    )
    new_payload_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header_b64}.{new_payload_b64}.{sig_b64}", debug.get("drv_name")


def main(trace_dir, marker):
    victim_name = sorted(os.listdir(trace_dir))[0]
    victim_path = os.path.join(trace_dir, victim_name)
    with open(victim_path) as f:
        body = json.load(f)
    tampered = [tamper_jws(jws, marker) for jws in body["signatures"]]
    body["signatures"] = [jws for jws, _ in tampered]
    drv_name = tampered[0][1] if tampered else None
    with open(victim_path, "w") as f:
        json.dump(body, f)
    # Stdout doubles as a smoke check for the test driver.
    print("victim_drv_name", drv_name)
    print("victim_hash", victim_name)
    print("tampered_signature_count", len(body["signatures"]))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
