import jwt
from typing import Dict
import subprocess
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from .utils import debug_print, get_output_hash

def get_all_outputs(drv_path: str) -> Dict[str, str]:
    """Get all output paths for a derivation"""
    try:
        result = subprocess.run(
            ['nix', 'derivation', 'show', drv_path],
            capture_output=True,
            text=True,
            check=True
        )
        deriv_json = json.loads(result.stdout)
        drv_data = deriv_json[drv_path]

        output_paths = {}
        if "outputs" in drv_data:
            for output_name, output_info in drv_data["outputs"].items():
                if isinstance(output_info, dict) and "path" in output_info:
                    output_path = output_info["path"]
                    output_hash = get_output_hash(output_path)
                    output_paths[output_name] = output_hash

        if not output_paths:
            raise ValueError("No outputs found for derivation")

        return output_paths
    except Exception as e:
        debug_print(f"Error getting outputs: {str(e)}")
        raise

def create_trace_signature(input_hash: str, drv_path: str, private_key: Ed25519PrivateKey, key_name: str) -> str:
    """
    Create a JWS signature for all outputs of a derivation

    Args:
        input_hash: The input hash of the derivation
        drv_path: Path to the derivation file
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

    # Get hashes for all outputs
    output_hashes = get_all_outputs(drv_path)
    debug_print(f"Creating signature with outputs: {output_hashes}")

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