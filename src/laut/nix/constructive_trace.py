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
    drv_str =  rfc8785.dumps(modified_drv).decode('utf-8')
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

def parse_aterm_as_python(aterm_str: str) -> tuple:
    """
    Parse an aterm by converting it to valid Python and evaluating it.
    This is safe because we control the input (it's from Nix).
    """
    # Replace Derive with a tuple constructor
    python_str = aterm_str.replace('Derive(', '(')
    
    # The aterm format uses empty strings for some fields, which is fine
    # We just need to evaluate it as a Python expression
    try:
        return eval(python_str)
    except Exception as e:
        raise ValueError(f"Failed to parse aterm as Python: {e}")

def format_aterm_from_tuple(aterm_tuple: tuple) -> str:
    """
    Convert a Python tuple back to aterm format.
    """
    # Convert the tuple back to string representation
    # We need to be careful to maintain the exact format
    import json
    
    def format_value(v):
        if isinstance(v, str):
            return json.dumps(v)  # This handles escaping properly
        elif isinstance(v, list):
            return '[' + ','.join(format_value(x) for x in v) + ']'
        elif isinstance(v, tuple):
            return '(' + ','.join(format_value(x) for x in v) + ')'
        else:
            raise ValueError(f"Unexpected type in aterm: {type(v)}")
    
    # Format all parameters
    params = [format_value(p) for p in aterm_tuple]
    return 'Derive(' + ','.join(params) + ')'

def resolve_aterm_dependencies(drv_aterm: str, resolutions: Optional[dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]]) -> str:
    """
    Resolve all dependencies in an aterm derivation by:
    1. Moving input derivations to inputSrcs as content hashes
    2. Replacing placeholders with content hashes
    
    Args:
        drv_aterm: The aterm string content
        resolutions: Map of unresolved to resolved derivations
        
    Returns:
        str: Modified aterm with resolved dependencies
    """
    from laut.nix import commands
    
    if resolutions is not None and resolutions == {}:
        # All dependencies already resolved
        return drv_aterm
    
    # Parse the aterm as Python
    # TODO: change this for security reasons
    aterm_tuple = parse_aterm_as_python(drv_aterm)
    
    # Extract components
    outputs = aterm_tuple[0]
    input_drvs = aterm_tuple[1]
    input_srcs = list(aterm_tuple[2])  # Convert to mutable list
    system = aterm_tuple[3]
    builder = aterm_tuple[4]
    args = aterm_tuple[5]
    env = aterm_tuple[6]
    
    # Process input derivations
    for drv_entry in input_drvs:
        drv_path_entry = drv_entry[0]
        outputs_list = drv_entry[1]
        
        if resolutions is not None:
            derivation = _get_typed_derivation(resolutions, drv_path_entry)
            for o in outputs_list:
                output_path = _get_content_hash(derivation, o)
                input_srcs.append(output_path)
        else:
            # Should not happen in verification mode
            if input_drvs:
                raise ValueError("Called with unresolved derivation and without resolution")
    
    # Sort inputSrcs for consistency
    input_srcs = sorted(input_srcs)
    
    # Create the resolved aterm with empty inputDrvs
    resolved_tuple = (outputs, [], input_srcs, system, builder, args, env)
    
    # Convert back to aterm string
    result = format_aterm_from_tuple(resolved_tuple)
    
    # Now replace placeholders throughout the aterm
    if resolutions is not None:
        for drv_entry in input_drvs:
            drv_path_entry = drv_entry[0]
            outputs_list = drv_entry[1]
            
            logger.debug(f"Processing input drv for placeholder replacement: {drv_path_entry}")
            
            drv_json = commands.get_derivation(drv_path_entry, False)
            is_fixed_output, is_ca = get_derivation_type(drv_json)
            if is_fixed_output:
                logger.debug(f"Skipping FOD: {drv_path_entry}")
                continue
                
            try:
                derivation = _get_typed_derivation(resolutions, drv_path_entry)
                for o in outputs_list:
                    # Replace placeholders (format: /[52-char-hash])
                    placeholder = derivation.placeholder_for(o)
                    content_hash = _get_content_hash(derivation, o)
                    logger.debug(f"Replacing placeholder {placeholder} with {content_hash}")
                    result = result.replace(placeholder, content_hash)
            except KeyError as e:
                logger.warning(f"Could not find resolution for {drv_path_entry}: {e}")
    
    return result

def compute_ATERMbased_resolved_input_hash(drv_path: str, drv_name: str, resolutions: Optional[dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]]) -> tuple[ResolvedInputHash, str]:
    """
    Compute the input hash for an aterm derivation with dependency resolution.
    
    Args:
        drv_path: Path to the derivation file
        drv_name: Name of the derivation
        resolutions: Map of unresolved to resolved derivations
        
    Returns:
        tuple: (resolved_input_hash, resolved_aterm_content)
    """
    with open(drv_path, 'r') as f:
        drv_aterm = f.read()
    
    resolved_aterm = resolve_aterm_dependencies(drv_aterm, resolutions)
    
    # Calculate the path/hash from the resolved aterm
    resolved_path = calculate_drv_path_from_aterm(drv_name, resolved_aterm)
    
    logger.debug(f"Resolved aterm drv {drv_path} to {resolved_path}")
    
    return resolved_path, resolved_aterm

@lru_cache(maxsize=None)
def cached_compute_JSONbased_resolved_input_hash(drv_path, resolution_tuple):
    resolution_dict = dict(resolution_tuple)
    return compute_JSONbased_resolved_input_hash(drv_path, resolution_dict)
