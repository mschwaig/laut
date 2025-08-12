import json
from pathlib import Path
import subprocess
import sys
from types import MappingProxyType
from typing import TypeVar, Dict, Iterator, Set, Iterator, Hashable
from itertools import product
from functools import wraps, cache
import os
import tempfile

from laut import config
from laut.nix.commands import (
    get_derivation_type
)
from laut.nix.constructive_trace import (
    compute_ATERMbased_resolved_input_hash
)
from laut.nix.deep_constructive_trace import (
    get_nix_path_input_hash,
    _extract_store_hash,
)
from laut.nix.types import (
    UnresolvedDerivation,
    UnresolvedOutput,
    UnresolvedReferencedInputs,
    ContentHash,
    TrustlesslyResolvedDerivation
)
from laut.verification.fetch_signatures import (
    fetch_and_verify_signatures,
    fetch_preimage_from_index
)
from loguru import logger
from laut.config import config
from lautr import TrustModelReasoner

from laut.verification.frogification import (
    inputs_to_string_list,
    outputs_to_string_list,
    signature_to_string_map_with_drv_path,
)

debug_dir = None

def get_all_outputs_of_drv(node_drv_path: str, is_content_addressed_drv: bool) -> Dict[str, UnresolvedOutput]:
    global _json
    output_json = _json[node_drv_path]["outputs"]
    if is_content_addressed_drv:
        outputs = {k: UnresolvedOutput(
            output_name=k,
            input_hash= None,
            drv_path=node_drv_path,
            unresolved_path = node_drv_path + "$" + k
        ) for k, v in output_json.items()}
    else:
        outputs = {k: UnresolvedOutput(
            output_name=k,
            drv_path=node_drv_path,
            input_hash = get_nix_path_input_hash(v["path"]),
            unresolved_path = v["path"]
        ) for k, v in output_json.items()}
    return outputs

def get_referenced_outputs_of_drv(depender: str, dedpendee_obj: UnresolvedDerivation) -> UnresolvedReferencedInputs:
    global _json
    referenced_str = _json[depender]["inputDrvs"][dedpendee_obj.drv_path]["outputs"]
    referenced_dict = { dedpendee_obj.outputs[r].output_name: dedpendee_obj.outputs[r] for r in referenced_str }
    referenced_obj = UnresolvedReferencedInputs(derivation=dedpendee_obj, inputs=referenced_dict)
    return referenced_obj

_json : Dict = {}
_reasoner : TrustModelReasoner = None

def _get_reasoner() -> TrustModelReasoner:
    """Lazy initialization of TrustModelReasoner"""
    global _reasoner
    if _reasoner is None:
        trusted_key_names = [key.name for key in config.trusted_keys]
        # For now, default threshold equals number of keys (current behavior)
        threshold = len(trusted_key_names)
        expected_root = config.expected_root
        if expected_root is None:
            raise ValueError("No expected root configured. This should be set before verification.")
        logger.warning(f"Initializing TrustModelReasoner with trusted keys: {trusted_key_names}, threshold: {threshold}, expected_root: {expected_root}")
        logger.warning(f"config.trusted_keys: {config.trusted_keys}")
        try:
            _reasoner = TrustModelReasoner(trusted_key_names, threshold, expected_root)
        except ValueError as e:
            logger.error(f"Failed to initialize TrustModelReasoner: {e}")
            raise
    return _reasoner

def build_unresolved_tree(node_drv_path: str, json: dict) -> UnresolvedDerivation:
    global _json
    _json = json
    build_unresolved_tree_rec.cache_clear()
    root_node = build_unresolved_tree_rec(node_drv_path)
    cache_info = build_unresolved_tree_rec.cache_info()
    logger.debug(cache_info)
    return root_node

@cache
def build_unresolved_tree_rec(node_drv_path: str) -> UnresolvedDerivation:
    global _json
    # TODO: canonicalize
    json_attrs = _json[node_drv_path]
    inputs = json_attrs["inputDrvs"]

    is_fixed_output, is_content_addressed_drv = get_derivation_type(json_attrs)
    outputs = get_all_outputs_of_drv(node_drv_path, is_content_addressed_drv)

    logger.debug(f"inputs: {inputs}")
    if is_fixed_output:
        input_outputs : Set[UnresolvedReferencedInputs] = set()
    elif is_content_addressed_drv or config.allow_ia:
        input_outputs = {
            get_referenced_outputs_of_drv(
                node_drv_path,
                build_unresolved_tree_rec(
                    drv_path
                )
            )
            for drv_path in inputs.keys()
        }
    else:
        raise ValueError("cannot handle IA derivations yet")

    unresolved_derivation = UnresolvedDerivation(
        drv_path=node_drv_path,
        json_attrs=json_attrs,
        input_hash=get_nix_path_input_hash(node_drv_path),
        inputs=input_outputs,
        outputs=outputs,
        is_content_addressed=is_content_addressed_drv, # this field should not really mater for FODs because they are leaves in the tree
        is_fixed_output=is_fixed_output,
    )
    #logger.debug(f"{unresolved_derivation}")
    #logger.debug(f"{list(unresolved_derivation.inputs)}")
    #logger.debug(f"{list(outputs)}")
    return unresolved_derivation

K = TypeVar('K', bound=Hashable)  # Key must be hashable (for dict keys)
V = TypeVar('V')

def get_resolution_combinations(input_resolutions: Dict[K, Set[V]]) -> Iterator[Dict[K, V]]:
    if len(input_resolutions) == 0:
        # if our dependency resolution has no variable parts
        # there is still one valid resolution with all of the static parts
        # so we return an empty dictionary here
        # this happens for sure on the outer edges of the dependency tree,
        # where all of your inputs are source code / blobs or outputs from a FOD
        yield {}
        return

    keys = list(input_resolutions.keys())

    resolution_lists = [list(input_resolutions[key]) for key in keys]

    for combination in product(*resolution_lists):
        yield dict(zip(keys, combination))

def reject_input_addressed_derivations(derivation: UnresolvedDerivation):
    for x in derivation.inputs:
        reject_input_addressed_derivations(x.derivation)
    raise ValueError("Not supporting input addressed derivations for now!")

def collect_valid_signatures_tree(derivation: UnresolvedDerivation) -> set[TrustlesslyResolvedDerivation]:
    global debug_dir
    global _reasoner
    # if our goal is not resolving a particular output
    # we go in trying to resolve all of them
    # TODO: return root and content of momoization cache here, since
    #       the content of the memoization cache has a "log entry" for each build step

    # Set the expected root in config for this verification
    config.expected_root = derivation.drv_path
    # Reset the global reasoner to ensure fresh state for each verification
    _reasoner = None

    with tempfile.TemporaryDirectory(delete=False) as temp_dir:

        td = Path(temp_dir)

        if config.debug:
            dir_path = td / "debug"
            os.mkdir(dir_path)
            debug_dir = Path(dir_path).resolve()


        root_result = collect_valid_signatures_tree_rec(derivation)

        # Compute final results using the trust model reasoner
        # The Rust code will print the verification results directly
        resolved_roots = _get_reasoner().compute_result()

        logger.warning(f"Trust model resolved roots: {resolved_roots}")
        logger.warning(f"Root result from signatures: {root_result}")

        # Verification is successful if we have any resolved roots
        # Note that the Rust code enforces the threshold requirement
        verification_success = len(resolved_roots) > 0

        logger.warning(f"Trust model verification success: {verification_success}")

        # If trust model verification failed, return empty set
        if not verification_success:
            logger.warning("Trust model verification failed - returning empty set")
            return set()

        return root_result

@cache
def collect_valid_signatures_tree_rec(unresolved_derivation: UnresolvedDerivation) -> set[TrustlesslyResolvedDerivation]:
    global debug_dir
    global _reasoner
    # if we invoke this with a FOD that should probably be an error?
    # we also should not recurse into FODs

    if unresolved_derivation.is_fixed_output:

        ct_input_hash, ct_input_data = compute_ATERMbased_resolved_input_hash(
            unresolved_derivation.drv_path, 
            unresolved_derivation.json_attrs["name"],
            dict() # tuple
        )
        _get_reasoner().add_fod(unresolved_derivation.drv_path, unresolved_derivation.json_attrs["outputs"]["out"]["path"])
        # TODO: lookup expected output hash and return it
        return {
            TrustlesslyResolvedDerivation(
                resolves = unresolved_derivation,
                drv_path = None,
                input_hash = ct_input_hash,
                # might not have to keep track of those two in python
                # TODO: maybe change exactly which attributes of the output are added here and in other places
                outputs = MappingProxyType({ unresolved_derivation.outputs["out"]: unresolved_derivation.json_attrs["outputs"]["out"]["path"] })
        )}

    _get_reasoner().add_unresolved_derivation(
        unresolved_derivation.drv_path,
        inputs_to_string_list(unresolved_derivation.inputs),
        outputs_to_string_list(unresolved_derivation.outputs))
    # use allowed DCT input hashes for verification before recursive descent
    # then check if result is sufficient so you can skip recursing
    # TODO: re-enable DCT verification
    #dct_signatures = _fetch_dct_signatures(inputs.derivation.input_hash)
    #valid = trust_model.dct_verify(inputs.derivation.input_hash, dct_signatures)
    step_result: dict[UnresolvedDerivation, set[TrustlesslyResolvedDerivation]] = dict()
    failed = False
    for i in unresolved_derivation.inputs:
        dep_result = collect_valid_signatures_tree_rec(i.derivation)
        # TODO: only tack outputs which we actually depend on
        if not dep_result:
            # nope out if we cannot resolve one of our dependencies
            failed = True
        step_result[i.derivation] = dep_result
    if failed:
        # could not resolve one of our dependencies
        return set()

    resolutions: Iterator[Dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]] = get_resolution_combinations(step_result)

    # we are not trying to fail early here
    # so we just want to collect all of the resolutions that we know about
    # and consider valid to some degree
    # and then use constraint solving to figure out what we are missing
    plausible_resolutions: set[TrustlesslyResolvedDerivation] = set()
    udrv_path = None
    if debug_dir:
        filename =  Path(unresolved_derivation.drv_path).name
        udrv_path = (debug_dir / filename).resolve()
        os.mkdir(udrv_path)
        with open(udrv_path / "u.drv", 'w') as f:
            f.write(json.dumps(unresolved_derivation.json_attrs))

    for resolution in resolutions:
        # Use aterm-based resolution instead of JSON-based
        ct_resolved_path, ct_input_data = compute_ATERMbased_resolved_input_hash(
            unresolved_derivation.drv_path,
            unresolved_derivation.json_attrs["name"],
            resolution
        )
        ct_input_hash = _extract_store_hash(ct_resolved_path)

        resolution_str = {}
        for unresolved_drv, resolved_drv in resolution.items():
            # Map each UnresolvedOutput to its corresponding content hash
            for unresolved_output, content_hash in resolved_drv.outputs.items():
                resolution_str[unresolved_output.udrv_output_id()] = content_hash
        _get_reasoner().add_resolved_derivation(unresolved_derivation.drv_path, ct_input_hash, resolution_str)

        if debug_dir:
            with open(udrv_path / ct_input_hash, 'w') as f:
                f.write(ct_input_data)
        signatures = fetch_and_verify_signatures(ct_input_hash)
        if not signatures and debug_dir and config.preimage_index:
            # if we cannot find signatures for a specific derivation,
            # we should do a another lookup in the builders file by the unresolved drv_hash for debugging purposes
            # and write that to a debug file, where the name indicates what it is
            # if we do not find such a file that might even lead to an exception,
            # because it points to incomplete test data
            # if we do find such a derivation, we should be able to use it to produce a sensible diff
            # between the input hash preimage on the signing and verification side
            for i in fetch_preimage_from_index(unresolved_derivation.json_attrs["name"]):
                drv_path, in_preimage = i
                with open(udrv_path / drv_path, 'w') as f:
                    f.write(in_preimage)
                process = subprocess.Popen(
                    ['difft', '--color', 'always', '--override=*:Python', udrv_path / ct_input_hash, udrv_path / Path(drv_path).name],
                    stdout=sys.stdout,
                    stderr=sys.stdout)
                process.wait()
        for signature_data, signing_key in signatures:
            # TODO: verify signature
            # TODO: deduplicate signatures by (in, out) before returning them
            outputs : Dict[UnresolvedOutput, ContentHash] = dict()
            _get_reasoner().add_build_output_claim(
                signature_data["in"]["rdrv_aterm_ca"],
                signature_to_string_map_with_drv_path(signature_data, unresolved_derivation.drv_path),
                signing_key
            )
            for o in signature_data["out"]["nix"]:
                # TODO: add output name or change data structure in some way to accommodate it
                outputs[unresolved_derivation.outputs[o]] = signature_data["out"]["nix"][o]["path"]
            if debug_dir:
                filename =  Path(signature_data["in"]["debug"]["rdrv_path"]).name
                with open(udrv_path / filename, 'w') as f:
                    f.write(signature_data["in"]["debug"]["rdrv_aterm_ca_preimage"])
                signed_hash = signature_data["in"]["rdrv_aterm_ca"]
                if ct_input_hash != signed_hash:
                    raise ValueError("hash must match file name")

            # Use the resolved path we computed, not the one from signature
            resolved_drv = TrustlesslyResolvedDerivation(
                resolves=unresolved_derivation,
                drv_path=ct_resolved_path,
                input_hash=ct_input_hash,
                outputs=MappingProxyType(outputs)
            )
            plausible_resolutions.add(resolved_drv)

    #    if valid:
    #        loguru.debug("validated {resolution} for {inputs.derivation.drv_path}")
    #        valid_resolutions.add((resolved_derivation, f"CT makes {resolution} a valid resolution for {inputs.derivation.drv_path}"))
    #    else:
    #        loguru.debug("failed to vaildate {resolution} for {inputs.derivation.drv_path}")

    return plausible_resolutions

def verify_tree_from_drv_path(drv_path):
    from laut.nix import commands
    all_drv_json = commands.get_derivation(drv_path, True)
    drv = build_unresolved_tree(drv_path, all_drv_json)
    resolved_derivations = collect_valid_signatures_tree(drv)

    # The CLI expects a truth-y value if verification succeeded
    # We'll return a non-empty string if verification succeeded, None otherwise
    if resolved_derivations and len(resolved_derivations) > 0:
        # Get the first resolved derivation
        first_resolved = next(iter(resolved_derivations))
        logger.info(f"Verification succeeded: {first_resolved}")
        # The CLI checks if this is truthy, so ensure we return a non-empty string
        return str(first_resolved) if first_resolved else "Verification successful"
    else:
        logger.warning("Verification failed: no resolved derivations found")
        return None
