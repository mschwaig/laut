def get_DCT_input_hash(drv_path: str) -> str:
    """
    Extract the deep contructive trace based input hash from a derivation path.
    """
    return _extract_store_hash(drv_path)

def _extract_store_hash(store_path):
    """
    Extract the hash portion from a Nix store path.
    
    Args:
        store_path (str): The full Nix store path
        
    Returns:
        str: The 32-character hash portion of the path
        
    Raises:
        ValueError: If the path doesn't match the expected Nix store path format
    """
    # Split the path into components
    components = store_path.split('/')
    
    # The last component should contain the hash and name
    if len(components) < 4 or not components[1] == "nix" or not components[2] == "store":
        raise ValueError("Invalid Nix store path format")
        
    last_component = components[-1]
    
    # The hash is always 32 characters at the start
    if len(last_component) < 33:  # 32 chars + at least 1 char for name
        raise ValueError("Invalid Nix store path format: component too short")
        
    hash_part = last_component[:32]
    
    # Verify the hash format (should be lowercase hex)
    if not all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in hash_part):
        raise ValueError("Invalid hash format in store path")
        
    return hash_part