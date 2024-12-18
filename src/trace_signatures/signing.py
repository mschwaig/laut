import jwt
from typing import Dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from .utils import debug_print

def create_trace_signature(input_hash: str, output_hashes: Dict[str, str], 
                         private_key: Ed25519PrivateKey, key_name: str) -> str:
    """
    Create a JWS signature for outputs

    Args:
        input_hash: The input hash of the derivation
        output_hashes: Dictionary mapping output names to their hashes
        private_key: Ed25519 private key for signing
        key_name: Name of the signing key

    Returns:
        str: The JWS signature token
    """
    headers = {
        "alg": "EdDSA",
        "type": "ntrace",
        "v": "1",
        "kid": key_name
    }

    debug_print(f"Creating signature for input hash {input_hash} with outputs {output_hashes}")

    payload = {
        "in": input_hash,
        "out": output_hashes,
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