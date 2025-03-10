import jwt
from typing import Dict
import os

from trace_signatures.verification.verification import get_derivation_type
from .storage import upload_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from .nix.keyfiles import (
    parse_nix_private_key,
)
from .nix.commands import (
    get_output_path,
    get_output_hash_from_disk,
)
from .nix.constructive_trace import (
    compute_CT_input_hash,
)
from .nix.commands import (
    get_derivation
)
from loguru import logger


def sign_and_upload(drv_path, secret_key_file, to, out_paths):
    # Get output names from derivation
    drv_data = get_derivation(drv_path)
    is_fixed_output, is_content_addressed = get_derivation_type(drv_data)
    if is_fixed_output:
        # TODO: this is left for very complicated future work on better guarantees for FODs
        return
    if is_content_addressed:
        # TODO: assert that keys in this data structure match out_paths
        output_hashes = drv_data["outputs"]
    else:
        # TODO: this is left for simpler future work on extending CAD guarantees to IADs
        return

    # Read key and create signature
    with open(secret_key_file[0], 'r') as f:
        content = f.read().strip()
    key_name = content.split(':', 1)[0]
    private_key = parse_nix_private_key(secret_key_file[0])

    input_hash, input_data = compute_CT_input_hash(drv_path, None)
    jws_token = create_trace_signature(input_hash, input_data, drv_path, output_hashes, private_key, key_name)
    logger.debug(f"{jws_token}")

    upload_signature(to, input_hash, jws_token)

def create_trace_signature(input_hash: str, input_data, drv_path: str, output_hashes: Dict,
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

    logger.debug(f"Creating signature for input hash {input_hash} with outputs {output_hashes}")

    payload = {
        "in": input_hash,
        "in_data": input_data,
        "drv_path": drv_path,
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
