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

def get_content_hash(drv_path):
    """
    Get the content hash for a derivation using nix-store --query --hash

    Args:
        drv_path: Path to the .drv file

    Returns:
        str: The content hash
    """
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', drv_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting hash for {drv_path}: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def resolve_dependencies(deriv_json):
    """
    Resolve all dependencies in a derivation by getting their content hashes
    and incorporating them into inputSrcs.

    Args:
        deriv_json: Parsed JSON derivation data

    Returns:
        dict: Modified derivation with resolved dependencies
    """
    # We'll work with the first (and typically only) derivation in the JSON
    drv_path = next(iter(deriv_json))
    drv_data = deriv_json[drv_path]

    # Get existing inputSrcs
    resolved_srcs = list(drv_data.get('inputSrcs', []))

    #  Get all input derivations and do not sort since we assume the order is meaningful
    input_drvs = drv_data.get('inputDrvs', {}).keys()

    # Get content hash for each input derivation and add to inputSrcs
    for drv in input_drvs:
        hash_path = get_content_hash(drv)
        resolved_srcs.append(hash_path)

    # Create modified derivation with resolved dependencies
    modified_drv = deriv_json.copy()
    modified_drv[drv_path]['inputSrcs'] = resolved_srcs
    modified_drv[drv_path]['inputDrvs'] = {}

    return modified_drv

def compute_sha256_base64(data):
    hash_bytes = hashlib.sha256(data).digest()
    return base64.b64encode(hash_bytes).decode('ascii')

def main():
    if len(sys.argv) != 2:
        print("Usage: canonical-derivation.py PATH")
        print("PATH can be a .drv file or a store path")
        sys.exit(1)

    path = sys.argv[1]

    # Get initial derivation
    canonical = get_canonical_derivation(path)
    initial_json = json.loads(canonical.decode('utf-8'))

    # Resolve dependencies
    resolved_json = resolve_dependencies(initial_json)

    # Canonicalize the resolved derivation
    resolved_canonical = rfc8785.dumps(resolved_json)

    # Compute final input hash
    final_hash = compute_sha256_base64(resolved_canonical)

    print(f"Resolved JSON: {resolved_canonical.decode('utf-8')}")
    print(f"Final SHA-256 (base64): {final_hash}")

if __name__ == '__main__':
    main()