from typing import List, Optional
import os
import copy
import struct
import json
import re

from loguru import logger

from laut.nix.constructive_trace import (
    compute_ATERMbased_input_hash
)
from laut.nix.commands import (
    get_derivation_type,
    get_output_hash_from_disk,
)
from laut.config import config
from lautr import (
    create_castore_entry,
    create_trace_signature,
    get_nix_path_input_hash,
    upload_signature,
)


def extract_nix_version_from_NIX_CONFIG(NIX_CONFIG_env_var: str):
    for line in NIX_CONFIG_env_var.splitlines():
        if line.startswith("build-hook ="):
            match = re.search(
                r"/nix/store/[a-z0-9]{32}-(lix|nix)-([a-zA-Z0-9.-_]+)/bin/nix",
                line,
            )
            if match:
                return match.groups()

    return (None, None)


def sign_and_upload_impl(drv_path, secret_key_file, to, out_paths: List[str]):
    result = sign_impl(drv_path, secret_key_file, out_paths)
    if result:
        input_hash, jws_token = result
        upload_signature(to, input_hash, jws_token)

def sign_impl(drv_path, secret_key_file, out_paths : List[str]) -> Optional[tuple[str, str]]:
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

    computed_drv_path, aterm_bytes = compute_ATERMbased_input_hash(drv_data["name"], drv_path)

    debug_data = {
        "drv_name": drv_data["name"],
        "rdrv_path": drv_path,
        "rdrv_computed_path": computed_drv_path,
        "rdrv_aterm_ca_preimage": aterm_bytes,
    } if config.include_preimage else None

    castore_outputs = { k: create_castore_entry(v["path"]) for k,v in output_hashes.items() }

    rebuild_id = struct.unpack('I', os.urandom(4))[0]

    NIX_CONFIG_env_var = os.getenv("NIX_CONFIG")
    builder_nix_flavor, builder_nix_version = None, None
    if NIX_CONFIG_env_var:
        builder_nix_flavor, builder_nix_version = extract_nix_version_from_NIX_CONFIG(NIX_CONFIG_env_var)

    # if a derivation were not able to observe its own name
    # we could factor out  the name before hashing
    # to get more cache hits
    input_hash = get_nix_path_input_hash(drv_path)

    jws_token = create_trace_signature(
        input_hash,
        json.dumps(debug_data) if debug_data is not None else None,
        json.dumps(output_hashes),
        json.dumps(castore_outputs),
        rebuild_id,
        builder_nix_flavor,
        builder_nix_version,
        secret_key_file[0],
    )
    logger.debug(f"{jws_token}")

    return input_hash, jws_token
