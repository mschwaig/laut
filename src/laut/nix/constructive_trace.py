from lautr import calculate_drv_path_from_aterm


def compute_ATERMbased_input_hash(drv_name: str, drv_path: str) -> tuple[str, str]:
    from laut.nix.commands import get_derivation_aterm
    drv_aterm = get_derivation_aterm(drv_path)
    path = calculate_drv_path_from_aterm(drv_name, drv_aterm)
    return path, drv_aterm
