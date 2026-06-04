from functools import lru_cache
import json

import lautr


def get_derivation_type(drv_data) -> tuple[bool, bool]:
    """Determine if a derivation is fixed-output and/or content-addressed."""
    outputs = drv_data.get("outputs", {})
    first_output = next(iter(outputs.values()), {})
    has_path = bool(first_output.get("path", False))
    has_hash = bool(first_output.get("hash", False))
    is_content_addressed_drv = (not has_path) and (not has_hash)
    is_fixed_output = has_hash
    return is_fixed_output, is_content_addressed_drv


@lru_cache(maxsize=None)
def get_derivation_aterm(drv_path: str) -> str:
    return lautr.nix_derivation_aterm(drv_path)


@lru_cache(maxsize=None)
def get_derivation(drv_path: str, recursive: bool):
    if recursive:
        return json.loads(lautr.nix_derivation_show_recursive(drv_path))
    return json.loads(lautr.nix_derivation_show(drv_path))[drv_path]


def get_output_hash_from_disk(out_path: str) -> str:
    return lautr.nix_output_hash_from_disk(out_path)
