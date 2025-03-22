import hashlib
from loguru import logger

def encode_to_string(src_bytes):
    """ Return the nixbase32 encoding of the input bytes. """
    """ ported from go-nix """
    ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"

    n = (len(src_bytes) * 8 + 4) // 5

    result = []

    for n_pos in range(n - 1, -1, -1):
        b = n_pos * 5
        i = b // 8
        j = b % 8

        c = src_bytes[i] >> j if i < len(src_bytes) else 0

        if i + 1 < len(src_bytes):
            c |= src_bytes[i + 1] << (8 - j)

        result.append(ALPHABET[c & 0x1f])

    return ''.join(result)

def is_valid_char(c):
    """ Check if a character is part of the nixbase32 alphabet. """
    """ ported from go-nix """
    return (
        ('0' <= c <= '9') or
        ('a' <= c <= 'z' and c not in 'eout')
    )

def from_drv_path_and_output(drv_path, output):
    components = drv_path[:-4].split('/')
    
    # The last component should contain the hash and name
    if len(components) < 4 or not components[1] == "nix" or not components[2] == "store":
        raise ValueError("Invalid Nix store path format")
        
    last_component = components[-1]
    
    # The hash is always 32 characters at the start
    if len(last_component) < 33:  # 32 chars + at least 1 char for name
        raise ValueError("Invalid Nix store path format: component too short")
        
    drv_hash = last_component[:32]
    drv_name = last_component[33:]
    
    # Verify the hash format (should be lowercase hex)
    if not all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in drv_hash):
        raise ValueError("Invalid hash format in store path")

    output_suffix = ""
    if output != "out":
        output_suffix = "-" + output
        

    return "/" + encode_to_string(hashlib.sha256(f"nix-upstream-output:{drv_hash}:{drv_name}{output_suffix}".encode('ascii')).digest())

