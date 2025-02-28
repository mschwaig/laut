from dataclasses import dataclass, field
from typing import Dict, Iterator, Set, Optional, List, Tuple
from functools import wraps, cache
import subprocess
import json
import itertools
import jwt
from nix_verify_souffle import SwigInterface

import os
import tempfile

from ..nix.commands import (
    get_derivation,
    check_nixos_cache,
    get_from_nixos_cache,
)
from ..nix.constructive_trace import (
    compute_CT_input_hash,
)
from ..nix.deep_constructive_trace import (
    get_DCT_input_hash,
)
from ..nix.types import (
    UnresolvedDerivation,
    UnresolvedOutput,
    UnresolvedReferencedInputs,
    UnresolvedInputHash,
    ResolvedInputHash,
    ResolvedDerivation,
    PossibleInputResolutions,
    TrustlesslyResolvedDerivation
)
from ..storage import get_s3_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)
from .trust_model import TrustedKey
from .fetch_signatures import fetch_ct_signatures
from loguru import logger

def get_derivation_type(drv_data) -> tuple[bool, bool]:
    """Determine if a derivation is fixed-output and/or content-addressed"""
    try:
        outputs = drv_data.get("outputs", {})
        first_output = next(iter(outputs.values()), {})
        has_path = bool(first_output.get("path", False))
        has_hash = bool(first_output.get("hash", False))
        is_content_addressed_drv =  (not has_path) and (not has_hash)
        is_fixed_output = has_hash

        return is_fixed_output, is_content_addressed_drv
    except Exception:
        logger.exception("error determining derivation type")
        raise

def get_all_outputs_of_drv(node_drv_path: str, is_content_addressed_drv: bool) -> Dict[str, UnresolvedOutput]:
    global _json
    output_json = _json[node_drv_path]["outputs"]
    if is_content_addressed_drv:
        outputs = {k: UnresolvedOutput(
            output_name=k,
            input_hash= None
        ) for k, v in output_json.items()}
    else:
        outputs = {k: UnresolvedOutput(
            output_name=k,
            input_hash= get_DCT_input_hash(v["path"])
        ) for k, v in output_json.items()}
    return outputs

def get_referenced_outputs_of_drv(depender: str, dedpendee_obj: UnresolvedDerivation) -> UnresolvedReferencedInputs:
    global _json
    referenced_str = _json[depender]["inputDrvs"][dedpendee_obj.drv_path]["outputs"]
    referenced_dict = { dedpendee_obj.outputs[r].output_name: dedpendee_obj.outputs[r] for r in referenced_str }
    referenced_obj = UnresolvedReferencedInputs(derivation=dedpendee_obj, inputs=referenced_dict)
    return referenced_obj

_json : Dict = {}

def build_unresolved_tree(node_drv_path: str, json: dict) -> UnresolvedDerivation:
    global _json
    _json = json
    root_node = build_unresolved_tree_rec(node_drv_path)
    cache_info = build_unresolved_tree_rec.cache_info()
    print(cache_info)
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
    else:
        input_outputs = {
            get_referenced_outputs_of_drv(
                node_drv_path,
                build_unresolved_tree_rec(
                    drv_path
                )
            )
            for drv_path in inputs.keys()
        }

    unresolved_derivation = UnresolvedDerivation(
        drv_path=node_drv_path,
        json_attrs=json_attrs,
        input_hash=get_DCT_input_hash(node_drv_path),
        inputs=input_outputs,
        outputs=outputs,
        is_content_addressed=is_content_addressed_drv, # this field shold not really mater for FODs because they are leafs in the tree
        is_fixed_output=is_fixed_output,
    )
    #logger.debug(f"{unresolved_derivation}")
    #logger.debug(f"{list(unresolved_derivation.inputs)}")
    #logger.debug(f"{list(outputs)}")
    return unresolved_derivation

def _get_resolution_combinations(input_resolutions: dict[UnresolvedDerivation, set[TrustlesslyResolvedDerivation]]) -> Iterator[dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]]:
    resolution_lists = [
        list(map(lambda x: x, list(resolutions)))
        #list(input_resolutions)
        for resolutions in input_resolutions.values()
    ]

    for combination in itertools.product(*resolution_lists):
        yield dict(zip(input_resolutions.keys(), combination))

def reject_input_addressed_derivations(derivation: UnresolvedDerivation):
    for x in derivation.inputs:
        reject_input_addressed_derivations(x.derivation)
    raise ValueError("Not supporting input addressed derivations for now!")

def verify_tree(derivation: UnresolvedDerivation, trust_model: TrustedKey) -> Tuple[set[TrustlesslyResolvedDerivation], dict]:
    # if our goal is not resolving a particular output
    # we go in trying to resolve all of them
    # TODO: return root and content of momoization cache here, since
    #       the content of the memoization cache has a "log entry" for each build step

    p = SwigInterface.newInstance("nix_verify")
    with tempfile.TemporaryDirectory() as temp_dir:

        unresolved_deps_file = open(os.path.join(temp_dir, 'unresolved_deps.facts'), 'w')
        drv_resolutions_file = open(os.path.join(temp_dir, 'drv_resolutions.facts'), 'w')
        resolved_deps_file = open(os.path.join(temp_dir, 'resolved_deps.facts'), 'w')
        builds_file = open(os.path.join(temp_dir, 'builds.facts'), 'w')
        
        root_result = verify_tree_rec(UnresolvedReferencedInputs(derivation=derivation, inputs=derivation.outputs), unresolved_deps_file, drv_resolutions_file, resolved_deps_file, builds_file)

        unresolved_deps_file.close()
        resolved_deps_file.close()
        builds_file.close()

        p.loadAll(temp_dir)
        p.run()

        p.dumpInputs()
        p.dumpOutputs()

        return (root_result,  verify_tree_rec.__wrapped__.cache)

def remember_steps(func):
    func.cache = dict()
    @wraps(func)
    def wrap_verify_tree_rec(*args):
        try:
            return func.cache[args[0]]
        except KeyError:
            func.cache[args[0]] = result = func(*args)
            return result
    return wrap_verify_tree_rec

@remember_steps
def verify_tree_rec(inputs: UnresolvedReferencedInputs, unresolved_deps_file, drv_resolutions_file, resolved_deps_file, builds_file) -> Set[TrustlesslyResolvedDerivation]:

    # if we invoke this with a FOD that should probably be an error?
    # we also should not recurse into FODs
    if inputs.derivation.is_fixed_output:
        ct_input_hash, ct_input_data = compute_CT_input_hash(inputs.derivation.drv_path, dict())
        return {TrustlesslyResolvedDerivation(
                resolves = inputs.derivation,
                input_hash = ct_input_hash,
                # might not have to keep track of those two in python
                inputs = dict(),
                outputs = { inputs.derivation.outputs["out"]: inputs.derivation.json_attrs["outputs"]["out"]["hash"]} # TODO: fix or remove, add algorithm
        )}

    # use allowed DCT input hashes for verification before recursive descent
    # then check if result is sufficient so you can skip recursing
    # TODO: re-enable DCT verification
    #dct_signatures = _fetch_dct_signatures(inputs.derivation.input_hash)
    #valid = trust_model.dct_verify(inputs.derivation.input_hash, dct_signatures)
    valid = False
    #if valid:
    #    return {( valid, f"DCT makes {inputs.derivation.drv_path} valid, not recursing further" )}
    # TODO: consider different outputs (only relevant for DCT)
    step_result: dict[UnresolvedDerivation, set[TrustlesslyResolvedDerivation]] = dict()
    failed = False
    for i in inputs.derivation.inputs:
        unresolved_deps_file.write(f"{inputs.derivation.drv_path}\t{i.derivation.drv_path}\n")
        dep_result = verify_tree_rec(i, unresolved_deps_file, drv_resolutions_file, resolved_deps_file, builds_file)
        if not dep_result:
            # nope out if we cannot resolve one of our dependencies
            failed = True
        step_result[i.derivation] = dep_result
    if failed:
        return set()

    if len(step_result) == 0:
        # nothing to resolve if all your dependencies are leafs in the tree
        # meaning none are derivations
        resolutions = [{}] # a list containing only an empty dictionary
    else:
        # otherwise we have at least one thing to resolve
        resolutions: list[dict[UnresolvedDerivation, ResolvedDerivation]] = list(_get_resolution_combinations(step_result))

    plausible_resolutions: set[TrustlesslyResolvedDerivation] = set()
    for resolution in resolutions:
        ct_input_hash, ct_input_data = compute_CT_input_hash(inputs.derivation.drv_path, resolution)

        drv_resolutions_file.write(f"{inputs.derivation.drv_path}\t\"{ct_input_hash}\"\n")
        for r in resolution.values():
            resolved_deps_file.write(f"\"{ct_input_hash}\"\t{r.resolves.drv_path}\t\"{r.input_hash}\"\n")
        for signature in fetch_ct_signatures(ct_input_hash):
            # TODO: verify signature
            # TODO: consider outputs other than out
            builds_file.write(f"\"{signature["in"]}\"\t\"{signature["out"]["out"]}\"\n")
            plausible_resolutions.add(TrustlesslyResolvedDerivation(
                   resolves = inputs.derivation,
                    input_hash = ct_input_hash,
                    # might not have to keep track of those two in python
                    inputs = resolution,
                    outputs = dict() # TODO: fix or remove
            ))

    #    if valid:
    #        print("vaildated {resolution} for {inputs.derivation.drv_path}")
    #        valid_resolutions.add((resolved_derivation, f"CT makes {resolution} a valid resolution for {inputs.derivation.drv_path}"))
    #    else:
    #        print("failed to vaildate {resolution} for {inputs.derivation.drv_path}")

    return plausible_resolutions
