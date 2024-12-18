import jwt
from typing import Dict
import subprocess
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from .utils import debug_print, get_output_hash

def get_output_mapping(drv_path: str) -> Dict[str, str]:
    """
    Get mapping of output names to their store paths for a derivation
    """
    try:
        # First get the derivation JSON to find output names
        result = subprocess.run(
            ['nix', 'derivation', 'show', drv_path],
            capture_output=True,
            text=True,
            check=True
        )
        deriv_json = json.loads(result.stdout)
        drv_data = deriv_json[drv_path]
        output_names = set(drv_data.get("outputs", {}).keys())

        if not output_names:
            raise ValueError("No outputs defined in derivation")

        debug_print(f"Found output names: {output_names}")

        # Then query the actual built paths
        result = subprocess.run(
            ['nix-store', '--query', '--outputs', drv_path],
            capture_output=True,
            text=True,
            check=True
        )

        output_paths = result.stdout.strip().split('\n')
        if not output_paths or not output_paths[0]:
            raise ValueError("No built outputs found")

        debug_print(f"Found output paths: {output_paths}")

        # Map output names to paths
        # By default, Nix orders outputs consistently, so we can zip them
        output_mapping = {}
        for name, path in zip(sorted(output_names), output_paths):
            if path:  # Only include paths that exist
                output_hash = get_output_hash(path)
                output_mapping[name] = output_hash

        if not output_mapping:
            raise ValueError("No valid outputs found for derivation")

        debug_print(f"Final output mapping: {output_mapping}")
        return output_mapping

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
    output_hashes = get_output_mapping(drv_path)
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