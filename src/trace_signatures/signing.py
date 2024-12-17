import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

def create_trace_signature(input_hash: str, output_hash: str, private_key: Ed25519PrivateKey, key_name: str):
    """Create a JWS signature"""
    headers = {
        "alg": "EdDSA",
        "type": "ntrace",
        "v": "1",
        "kid": key_name  # Add key ID to header
    }

    payload = {
        "in": input_hash,
        "out": output_hash,
        "builder": {
            "rebuild": "1",
        }
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=headers
    )