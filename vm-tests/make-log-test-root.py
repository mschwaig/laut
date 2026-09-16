"""Deterministic PUBLIC TEST KEYS and a standard private-log TrustedRoot."""
import base64
import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
for name, seed in [("log", 9), ("wrong-log", 10)]:
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = key.public_key()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    log_id = hashlib.sha256(b"rekor\n\x01" + raw).digest()
    (out / f"{name}.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    root = {"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": [{
        "baseUrl": "http://rekor", "hashAlgorithm": "SHA2_256",
        "logId": {"keyId": base64.b64encode(log_id).decode()},
        "publicKey": {"keyDetails": "PKIX_ED25519", "rawBytes": base64.b64encode(der).decode(),
                      "validFor": {"start": "2020-01-01T00:00:00Z"}},
    }]}
    (out / f"{name}-root.json").write_text(json.dumps(root))
