#! /usr/bin/env -S python3 -u
import subprocess
import json
import sys
import rfc8785
import hashlib
import base64

def get_canonical_derivation(path):
    """
    Get a canonicalized JSON representation of a Nix derivation.
    
    Args:
        path: Path to .drv file or Nix store path
        
    Returns:
        bytes: Canonicalized JSON bytes of the derivation
    """
    try:
        # Run nix derivation show
        result = subprocess.run(
            ['nix', 'derivation', 'show', path],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the JSON output
        deriv_json = json.loads(result.stdout)
        
        # Canonicalize using JCS
        return rfc8785.dumps(deriv_json)
        
    except subprocess.CalledProcessError as e:
        print(f"Error running 'nix derivation show': {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing derivation JSON: {e}", file=sys.stderr)
        sys.exit(1)

def compute_sha256_base64(data):
    hash_bytes = hashlib.sha256(data).digest()
    return base64.b64encode(hash_bytes).decode('ascii')

def main():
    if len(sys.argv) != 2:
        print("Usage: canonical-derivation.py PATH")
        print("PATH can be a .drv file or a store path")
        sys.exit(1)
    
    path = sys.argv[1]
    canonical = get_canonical_derivation(path)
    sha256_hash = compute_sha256_base64(canonical)
    print(f"Canonical JSON: {canonical.decode('utf-8')}")
    print(f"SHA-256 (base64): {sha256_hash}")

if __name__ == '__main__':
    main()