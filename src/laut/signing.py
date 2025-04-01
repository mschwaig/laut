import jwt
from typing import Dict, Optional
import os
import copy

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
from laut.nix.commands import (
    get_derivation_type
)
from laut.config import config
from loguru import logger

def sign_and_upload_impl(drv_path, secret_key_file, to, out_paths):
    result = sign_impl(drv_path, secret_key_file, out_paths)
    if result:
        input_hash, jws_token = result
        upload_signature(to, input_hash, jws_token)

def sign_impl(drv_path, secret_key_file, out_paths) -> Optional[tuple[str, str]]:
    from laut.nix import commands
    drv_data = commands.get_derivation(drv_path, False)
    if drv_data['inputDrvs'] != {}:
        # we have to return gracefully in this case, because
        # nix calls the post-build-hook twice
        # once for the resolved derivation
        # once for the unresolved one
        logger.warning("doing nothing on unresolved derivation")
        return None

    output_names = list(drv_data.get("outputs", {}).keys())
    is_fixed_output, is_content_addressed = get_derivation_type(drv_data)
    if is_fixed_output:
        # TODO: this is left for very complicated future work on better guarantees for FODs
        return None
    if is_content_addressed:
        # TODO: assert that keys in this data structure match out_paths
        output_hashes = copy.deepcopy(drv_data["outputs"])
        for path in out_paths:
            # Extract the output name from path suffix
            for name in output_names:
                if path.endswith(f"-{name}") or (name == "out" and not any(path.endswith(f"-{n}") for n in output_names)):
                    output_hashes[name]["path"] = path
                    # we can probably drop this next line in favor of just the path
                    # potentially even get rid of that whole complex object again
                    # if not we should assert that the prefix is correct and then drop it
                    output_hashes[name]["hash"] = get_output_hash_from_disk(path)
                    break
    else:
        # TODO: for now this is left for future work on extending CA derivation guarantees to IA derivations
        logger.exception(f"not handeling IA derivation {drv_path}")
        return None

    # Read key and create signature
    with open(secret_key_file[0], 'r') as f:
        content = f.read().strip()
    key_name = content.split(':', 1)[0]
    private_key = parse_nix_private_key(secret_key_file[0])

    # TODO: construct resolution from all of the local derivation inputs >:(

    input_hash, input_data = compute_CT_input_hash(drv_path, None)
    jws_token = create_trace_signature(input_hash, input_data, drv_path, output_hashes, private_key, key_name)
    logger.debug(f"{jws_token}")

    return input_hash, jws_token

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
        **({"in_preimage": input_data} if config.debug else {}),
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
