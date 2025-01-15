from dataclasses import dataclass, field
from typing import Dict, Set, Optional, List
from functools import cache
import subprocess
import json
import itertools
import jwt
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
    ResolvedDerivation
)
from ..storage import get_s3_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)
from verification.trust_model import TrustModel
from loguru import logger

def get_derivation_type(drv_data) -> tuple[bool, bool]:
    """Determine if a derivation is fixed-output and/or content-addressed"""
    try:
        # Check for fixed-output
        env = drv_data.get("env", {})
        is_fixed_output = bool(env.get("outputHash", ""))

        # Check for content-addressing
        is_content_addressed = bool(drv_data.get("__contentAddressed", False))

        return is_fixed_output, is_content_addressed
    except Exception:
        logger.exception("error determining derivation type")
        raise

def get_all_outputs_of_drv(node_drv_path: str) -> Dict[str, UnresolvedOutput]:
    global _json
    output_json = _json[node_drv_path]["outputs"]
    #logger.debug(f"output_json: {output_json}")
    outputs = {k: UnresolvedOutput(
        output_name=k,
        input_hash=get_DCT_input_hash(v["path"])
    ) for k, v in output_json.items()}
    #logger.debug(f"outputs: {outputs}")
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

    is_fixed_output, is_content_addressed = get_derivation_type(json_attrs)
    outputs = get_all_outputs_of_drv(node_drv_path)

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
        is_content_addressed=is_content_addressed,
        is_fixed_output=is_fixed_output,
    )
    #logger.debug(f"{unresolved_derivation}")
    #logger.debug(f"{list(unresolved_derivation.inputs)}")
    #logger.debug(f"{list(outputs)}")
    return unresolved_derivation

# We might want to track UnresolvedReferencedInputs here,
# to deal with DCTs
# This cannot be replaced with memoization, because we only
# want to produce results a limited number of times.
_visited: set[UnresolvedDerivation] = set()


def _fetch_ct_signatures(input_hash: ResolvedInputHash):
    return
def _fetch_dct_signatures(input_hash: UnresolvedInputHash):
    return

def reject_input_addressed_derivations(derivation: UnresolvedDerivation):
    for x in derivation.inputs:
        reject_input_addressed_derivations(x.derivation)
    raise ValueError("Not supporting input addressed derivations for now!")

def verify_tree(derivation: UnresolvedDerivation, trust_model: TrustModel) -> tuple[Set[ResolvedDerivation], List[str]]:
    # if our goal is not resolving a particular output
    # we go in trying to resolve all of them
    return verify_tree_rec(UnresolvedReferencedInputs(derivation=derivation, inputs=derivation.outputs), trust_model)

def verify_tree_rec(inputs: UnresolvedReferencedInputs, trust_model: TrustModel) -> tuple[Set[ResolvedDerivation], List[str]]:
    global _visited
    if inputs.derivation in _visited:
        return (set(), [])
    else:
        _visited.add(inputs.derivation)
    # use allowed DCT input hashes for verification before recursive descent
    # then check if result is sufficient so you can skip recursing
    dct_signatures = _fetch_dct_signatures(inputs.derivation.input_hash)
    valid = trust_model.dct_verify(inputs.derivation.input_hash, dct_signatures)
    if valid:
        return ( valid, [ f"DCT makes {inputs.derivation.drv_path} valid, not recursing further" ] )
    # TODO: consider different outputs
    result: tuple[Set[ResolvedDerivation], List[str]] = (set(),[])
    for i in inputs.derivation.inputs:
        result_i = verify_tree_rec(i, trust_model)
        result = (result[0].union(result_i[0]), result[1] + result_i[1])

    ct_signatures = _fetch_ct_signatures(inputs.derivation.input_hash)

    valid = trust_model.ct_verify(inputs.derivation.input_hash, ct_signatures)
    result_message: str
    if valid:
        result_message = f"CT makes {inputs.derivation.drv_path} valid"
        result = (result[0].union(valid), result[1] + [  ])
    else:
        result_message = f"CT makes {inputs.derivation.drv_path} valid"

    result = (result[0].union(valid), result[1] + [ result_message ])

    return result
    # we're on the way back down the tree now
    # use CT input hashes to check properly check chains
    # we need to do this using all possible resolved dependency trees now

    # for each node we should be able to make a determination if it was sufficiently verified
