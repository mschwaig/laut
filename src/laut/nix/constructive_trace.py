from typing import Optional

from laut.nix.types import (
    TrustlesslyResolvedDerivation,
    UnresolvedDerivation,
    ResolvedInputHash,
)
from lautr import (
    calculate_drv_path_from_aterm,
    compute_aterm_resolved_input_hash,
)


def compute_ATERMbased_input_hash(drv_name: str, drv_path: str) -> tuple[ResolvedInputHash, str]:
    from laut.nix.commands import get_derivation_aterm
    drv_aterm = get_derivation_aterm(drv_path)
    path = calculate_drv_path_from_aterm(drv_name, drv_aterm)
    return path, drv_aterm


def compute_ATERMbased_resolved_input_hash(
    drv_path: str,
    drv_name: str,
    resolutions: Optional[dict[UnresolvedDerivation, TrustlesslyResolvedDerivation]],
) -> tuple[ResolvedInputHash, str]:
    """
    Compute the resolved input hash for an unresolved derivation by editing its
    ATerm: drop inputDrvs, fold resolved content-hash paths into inputSrcs, and
    replace upstream-output placeholders with their resolved hashes.
    """
    from laut.nix.commands import get_derivation_aterm
    drv_aterm = get_derivation_aterm(drv_path).encode("utf-8")

    str_resolutions: dict[str, dict[str, str]] = {}
    if resolutions:
        for unresolved_drv, resolved_drv in resolutions.items():
            outputs_for_drv: dict[str, str] = {}
            for unresolved_output, content_hash in resolved_drv.outputs.items():
                outputs_for_drv[unresolved_output.output_name] = content_hash
            str_resolutions[unresolved_drv.drv_path] = outputs_for_drv

    return compute_aterm_resolved_input_hash(drv_name, drv_aterm, str_resolutions)
