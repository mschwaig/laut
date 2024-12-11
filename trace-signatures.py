#! /usr/bin/env -S python3 -u
import subprocess
import json
import sys
import rfc8785
import hashlib
import base64
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    """
    # We'll work with the first (and typically only) derivation in the JSON
    drv_path = next(iter(deriv_json))
    drv_data = deriv_json[drv_path]

    # Get existing inputSrcs
    resolved_srcs = list(drv_data.get('inputSrcs', []))

    # Get all input derivations and do not sort since we assume the order is meaningful
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
    """Compute SHA-256 hash and return base64 encoded"""
    hash_bytes = hashlib.sha256(data).digest()
    return base64.b64encode(hash_bytes).decode('ascii')

def get_output_hash(path):
    """Get the content hash of the built output"""
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting output hash for {path}: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def parse_nix_key_file(key_path):
    """
    Parse a Nix signing key file in the format 'name:base64key'
    The key is in libsodium format: 64 bytes (32 byte key + 32 byte salt)
    """
    with open(key_path, 'r') as f:
        content = f.read().strip()

    name, key_b64 = content.split(':', 1)
    key_bytes = base64.b64decode(key_b64)
    
    # Extract just the private key (first 32 bytes)
    private_key_bytes = key_bytes[:32]

    return Ed25519PrivateKey.from_private_bytes(private_key_bytes)

def create_trace_signature(input_hash: str, output_hash: str, private_key):
    """Create a JWS signature in the specified format"""
    headers = {
        "alg": "EdDSA",
        "type": "ntrace",
        "v": "1"
    }

    payload = {
        "in": input_hash,
        "out": output_hash,
        "builder": {
            "rebuild": "1",
        }
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=headers
    )

def main():
    if len(sys.argv) != 3:
        print("Usage: trace-signatures.py DRV_PATH PRIVATE_KEY_PATH")
        sys.exit(1)

    drv_path = sys.argv[1]
    private_key_path = sys.argv[2]

    # Parse the private key file
    private_key = parse_nix_key_file(private_key_path)

    # Get initial derivation
    canonical = get_canonical_derivation(drv_path)
    initial_json = json.loads(canonical.decode('utf-8'))

    # Resolve dependencies
    resolved_json = resolve_dependencies(initial_json)

    # Canonicalize the resolved derivation
    resolved_canonical = rfc8785.dumps(resolved_json)

    # Compute final input hash
    input_hash = compute_sha256_base64(resolved_canonical)

    # Get the output path from the derivation
    drv_path_key = next(iter(initial_json))
    output_path = initial_json[drv_path_key]['outputs']['out']['path']

    # Get output hash
    output_hash = get_output_hash(output_path)

    # Create JWS
    jws_token = create_trace_signature(input_hash, output_hash, private_key)

    print(jws_token)

if __name__ == '__main__':
    main()