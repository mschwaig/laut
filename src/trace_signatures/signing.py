import base64
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .utils import debug_print

def parse_nix_key_file(key_path):
    """Parse a Nix signing key file"""
    with open(key_path, 'r') as f:
        content = f.read().strip()

    name, key_b64 = content.split(':', 1)
    key_bytes = base64.b64decode(key_b64)
    private_key_bytes = key_bytes[:32]
    return Ed25519PrivateKey.from_private_bytes(private_key_bytes)

def create_trace_signature(input_hash: str, output_hash: str, private_key):
    """Create a JWS signature"""
    headers = {
        "alg": "EdDSA",
        "type": "ntrace",
        "v": "1"
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