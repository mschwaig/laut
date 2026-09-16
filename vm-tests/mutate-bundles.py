"""Adversarial mutations of private-test bundles, never public infrastructure."""
import base64
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
for path in directory.iterdir():
    if not path.is_file():
        continue
    bundles = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for bundle in bundles:
        envelope = bundle["dsseEnvelope"]
        entries = bundle["verificationMaterial"].get("tlogEntries", [])
        if mode == "strip":
            bundle["verificationMaterial"].pop("tlogEntries", None)
        elif mode == "payload":
            payload = json.loads(base64.b64decode(envelope["payload"]))
            payload["predicate"]["buildDefinition"]["externalParameters"]["resolvedInputHash"] = "0" * 32
            envelope["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
        elif mode == "signature":
            envelope["signatures"][0]["sig"] = base64.b64encode(bytes(64)).decode()
        else:
            for entry in entries:
                if mode == "checkpoint":
                    entry["inclusionProof"]["checkpoint"]["envelope"] = entry["inclusionProof"]["checkpoint"]["envelope"].replace("rekor", "wrong")
                elif mode == "proof":
                    entry["inclusionProof"]["hashes"].append(base64.b64encode(bytes(32)).decode())
                elif mode == "index":
                    entry["logIndex"] = "9223372036854775807"
                elif mode in ("binding", "verifier"):
                    body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
                    metadata = body["spec"]["hashedRekordV002"]
                    if mode == "binding":
                        metadata["data"]["digest"] = base64.b64encode(bytes(64)).decode()
                    else:
                        metadata["signature"]["verifier"]["publicKey"]["rawBytes"] = base64.b64encode(bytes(44)).decode()
                    entry["canonicalizedBody"] = base64.b64encode(json.dumps(body).encode()).decode()
                else:
                    raise ValueError(mode)
    path.write_text("".join(json.dumps(b, separators=(",", ":")) + "\n" for b in bundles))
