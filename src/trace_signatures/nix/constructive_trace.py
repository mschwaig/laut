import subprocess
import hashlib
import base64
from loguru import logger
from .commands import (
    get_derivation,
    get_output_hash
)
import rfc8785

def get_canonical_derivation(path):
    """Get canonicalized JSON representation of a Nix derivation"""
    deriv_json = get_derivation(path)
    return rfc8785.dumps(deriv_json)

def compute_sha256_base64(data: bytes):
    """Compute SHA-256 hash and return URL-safe base64 encoded"""
    logger.debug(f"Input type: {type(data)}")
    logger.debug(f"Input data: {data}...")
    hash_bytes = hashlib.sha256(data).digest()
    result = base64.urlsafe_b64encode(hash_bytes).decode('ascii').rstrip('=')
    logger.debug(f"Computed hash: {result}")
    return result

def resolve_dependencies(drv_data, resolutions):
    """
    Resolve all dependencies in a derivation by getting their content hashes
    and incorporating them into inputSrcs.

    Args:
        drv_data: Parsed JSON derivation data

    Returns:
        dict: Modified derivation with resolved dependencies
    """
    # Get existing inputSrcs
    resolved_srcs = list(drv_data.get('inputSrcs', []))

    #  Get all input derivations and do not sort since we assume the order is meaningful
    input_drvs = drv_data.get('inputDrvs', {}).keys()

    # Get content hash for each input derivation and add to inputSrcs
    if resolutions:
        resolved_srcs.append(resolutions)
    else:
        for drv in input_drvs:
            hash_path = get_output_hash(drv)
            resolved_srcs.append(hash_path)

    # Create modified derivation with resolved dependencies
    modified_drv = drv_data.copy()
    modified_drv['inputSrcs'] = resolved_srcs
    modified_drv['inputDrvs'] = {}

    return modified_drv
f
def compute_derivation_input_hash(drv_path: str, resolutions) -> str:
    """
    Compute the input hash for a derivation path.
    This is the central function that should be used by both signing and verification.
    """
    unresolved_drv_json = get_derivation(drv_path)
    resolved_drv_json = resolve_dependencies(unresolved_drv_json, resolutions)
    resolved_canonical = rfc8785.dumps(resolved_drv_json)
    resolved_input_hash = compute_sha256_base64(resolved_canonical)

    print(f"Resolved JSON: {resolved_canonical.decode('utf-8')}")
    print(f"Final SHA-256 (base64): {resolved_input_hash}")

    return resolved_input_hash
