import subprocess
import hashlib
import base64
from loguru import logger
from trace_signatures.nix.types import (
    UnresolvedDerivation,
    ResolvedDerivation,
    ResolvedInputHash
)
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
    for drv in input_drvs:
        # TODO: make sure we are considering different outputs per derivation in both code paths here
        if resolutions:
            # if we cannot resolve something
            # we should make sure to throw an exception here
            hash_path = resolutions[drv]
        else:
            hash_path = get_output_hash(drv)
        resolved_srcs.append(hash_path)

    # Create modified derivation with resolved dependencies
    modified_drv = drv_data.copy()
    modified_drv['inputSrcs'] = resolved_srcs
    modified_drv['inputDrvs'] = {}

    return modified_drv

def compute_CT_input_hash(drv_path: str, resolutions: dict[UnresolvedDerivation, ResolvedDerivation]) -> tuple[ResolvedInputHash, str]:
    """
    Compute the input hash for a derivation path.
    This is the central function that should be used by both signing and verification.
    """
    unresolved_drv_json = get_derivation(drv_path)
    resolved_drv_json = resolve_dependencies(unresolved_drv_json, resolutions)
    resolved_canonical = rfc8785.dumps(resolved_drv_json)
    resolved_input_hash = compute_sha256_base64(resolved_canonical)
    hash_input = resolved_canonical.decode('utf-8')

    print(f"Resolved JSON: {hash_input}")
    print(f"Final SHA-256 (base64): {resolved_input_hash}")

    return resolved_input_hash, hash_input
