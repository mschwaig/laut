def get_derivation_json(drv_path: str) -> dict:
    """Get JSON representation of a derivation"""
    
def get_output_names(drv_path: str) -> Set[str]:
    """Get output names for a derivation"""
    
def get_derivation_type(drv_path: str) -> tuple[bool, bool]:
    """Get if derivation is fixed-output and/or content-addressed"""
    
def resolve_flake_to_drv(flake_ref: str) -> str:
    """
    Resolve a flake reference to a derivation path
    Example: nixpkgs#hello -> /nix/store/...drv
    """
    result = subprocess.run(
        ['nix', 'eval', '--raw', f'{flake_ref}.drvPath'],
        capture_output=True,
        text=True,
        check=True
    )
    drv_path = result.stdout.strip()
    debug_print(f"Resolved {flake_ref} to {drv_path}")
    return drv_path
    
def get_output_path(drv_path: str) -> str:
    """Get output path for derivation"""
    
def get_output_hash(path: str) -> str:
    """Get hash of a store path"""