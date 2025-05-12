from functools import lru_cache
import json
import hashlib
import base64
from typing import Optional

from loguru import logger
import rfc8785

from laut.nix.types import (
    TrustlesslyResolvedDerivation,
    UnresolvedDerivation,
    ResolvedInputHash,
    UnresolvedOutput,
    ContentHash
)
from laut.nix.commands import (
    get_derivation_type
)
from lautr import calculate_drv_path_from_aterm

def get_canonical_derivation(path):
    """Get canonicalized JSON representation of a Nix derivation"""
    from laut.nix import commands
    deriv_json = commands.get_derivation(path, False)
    return rfc8785.dumps(deriv_json)

def compute_sha256_base64(data: bytes):
    """Compute SHA-256 hash and return URL-safe base64 encoded"""
    hash_bytes = hashlib.sha256(data).digest()
    result = base64.urlsafe_b64encode(hash_bytes).decode('ascii').rstrip('=')
    return result

def _get_typed_derivation(dict: dict[UnresolvedDerivation, TrustlesslyResolvedDerivation], drv_path) -> TrustlesslyResolvedDerivation:
    for entry in dict:
        if entry.drv_path == drv_path:
            return dict[entry]

    raise KeyError("failed to find drv §{drv_path}")

def _get_content_hash(drv: TrustlesslyResolvedDerivation, out) -> ContentHash:
    for o in drv.outputs:
        if o.output_name == out:
            return drv.outputs[o]

    raise KeyError("failed to find output §{drv_path}")

def _get_output(drv: TrustlesslyResolvedDerivation, out) -> UnresolvedOutput:
    for o in drv.outputs:
        if o.output_name == out:
            return o

    raise KeyError("failed to find output §{drv_path}")

# TODO: maybe we should fail dependency resolution
#       if there is anything left in the derivation
#       that looks like a placeholder
#       except for the output ones, which I think are fine
def resolve_dependencies(drv_data, resolutions: Optional[dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]]):
    """
    Resolve all dependencies in a derivation by getting their content hashes
    and incorporating them into inputSrcs.

    Args:
        drv_data: Parsed JSON derivation data

    Returns:
        dict: Modified derivation with resolved dependencies
    """
    from laut.nix import commands
    if (resolutions != None) and (resolutions == {}):
        # we have a set of resolutions, so we are in verification 'mode', but
        # all dependencies are already fully resolved
        return drv_data

    # Get existing inputSrcs
    resolved_srcs = list(drv_data.get('inputSrcs', []).copy())

    #  Get all input derivations and do not sort since we assume the order is meaningful
    input_drvs = drv_data.get('inputDrvs', {})

    # Get content hash for each input derivation and add to inputSrcs
    for drv in input_drvs:
        # TODO: make sure we are considering different outputs per derivation in both code paths here
        if resolutions != None:
            # if we cannot resolve something
            # we should make sure to throw an exception here
            derivation = _get_typed_derivation(resolutions, drv)
            for o in input_drvs[drv]["outputs"]:
                output_hash = _get_content_hash(derivation, o)
                resolved_srcs.append(output_hash)
        else:
            # for CADs we should get called with the resolved/basic derivation
            # so there should not be any further resolution that we have to do
            # TODO: extend this to deal with IADs
            if drv_data['inputDrvs'] != {}:
                raise ValueError("called with unresolved derivation and without resolution")
            #for o in input_drvs[drv]["outputs"]:
                #output_hash = get_output_hash_from_disk(f"{drv}${o}")
                # TODO: this should probably not just be the raw hash, but also some metadata about its format
                # TODO: we probably don't care about "path" here, maybe we can make a whitelist of things we care about

                #resolved_srcs.append(output_hash)

    # Create modified derivation with resolved dependencies
    modified_drv = drv_data.copy()
    modified_drv['inputSrcs'] = list(sorted(resolved_srcs))
    modified_drv['inputDrvs'] = {}

    # for each key and value of the resolution thing
    # check if it occurs in the modified derivation and replace it
    drv_str =  rfc8785.dumps(modified_drv).decode('ascii')
    for drv in input_drvs:
        drv_json = commands.get_derivation(drv, False)
        is_fixed_output, is_ca = get_derivation_type(drv_json)
        if is_fixed_output:
            continue
        # TODO: make sure we are considering different outputs per derivation in both code paths here
        if resolutions != None:
            # if we cannot resolve something
            # we should make sure to throw an exception here
            derivation = _get_typed_derivation(resolutions, drv)
            for o in input_drvs[drv]["outputs"]:
                drv_str = drv_str.replace(derivation.placeholder_for(o), _get_content_hash(derivation, o))
                drv_str = drv_str.replace(derivation.resolves.outputs[o].placeholder(), _get_content_hash(derivation, o))

    ret_str = json.loads(drv_str)
    return ret_str

def compute_JSONbased_resolved_input_hash(drv_path: str, resolutions: Optional[dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]]) -> tuple[ResolvedInputHash, str]:
    """
    Compute the input hash for a derivation path.
    This is the central function that should be used by both signing and verification.
    """
    from laut.nix import commands
    unresolved_drv_json = commands.get_derivation(drv_path, False)
    resolved_drv_json = resolve_dependencies(unresolved_drv_json, resolutions)
    resolved_canonical = rfc8785.dumps(resolved_drv_json)
    resolved_input_hash = compute_sha256_base64(resolved_canonical)
    hash_input = resolved_canonical.decode('utf-8')

    logger.debug(f"resolved drv {drv_path} to {resolved_input_hash}")
    #logger.info(f"Resolved JSON: {hash_input}")

    return resolved_input_hash, hash_input

def compute_ATERMbased_resolved_input_hash_like_nix(drv_name: str, drv_path: str) -> tuple[ResolvedInputHash, str]:
    with open(drv_path, 'r') as content_file:
        drv_aterm = content_file.read()

    path = calculate_drv_path_from_aterm(drv_name, drv_aterm)

    return path, drv_aterm

@lru_cache(maxsize=None)
def cached_compute_JSONbased_resolved_input_hash(drv_path, resolution_tuple):
    resolution_dict = dict(resolution_tuple)
    return compute_JSONbased_resolved_input_hash(drv_path, resolution_dict)
