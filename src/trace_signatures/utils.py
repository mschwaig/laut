import subprocess
import json
import sys
import hashlib
import base64
import rfc8785

def debug_print(msg):
    """Print debug message to stderr"""
    print(f"DEBUG: {msg}", file=sys.stderr)

def get_output_path(drv_path):
    """Get the output path for a derivation"""
    debug_print(f"Getting output path for derivation: {drv_path}")
    try:
        result = subprocess.run(
            ['nix', 'path-info', f'{drv_path}^*'],
            capture_output=True,
            text=True,
            check=True
        )
        outputs = result.stdout.strip().split('\n')
        if outputs and outputs[0]:
            debug_print(f"Found CA derivation output: {outputs[0]}")
            return outputs[0]

        canonical = get_canonical_derivation(drv_path)
        deriv_json = json.loads(canonical.decode('utf-8'))
        debug_print(f"Derivation JSON structure: {json.dumps(deriv_json, indent=2)}")

        drv_data = deriv_json[drv_path]
        if 'outputs' in drv_data and 'out' in drv_data['outputs']:
            output_data = drv_data['outputs']['out']
            if isinstance(output_data, dict) and 'path' in output_data:
                debug_print(f"Found input-addressed output path: {output_data['path']}")
                return output_data['path']

        raise ValueError("Could not determine output path")
    except Exception as e:
        debug_print(f"Error getting output path: {str(e)}")
        raise

def get_canonical_derivation(path):
    """Get canonicalized JSON representation of a Nix derivation"""
    try:
        debug_print(f"Running nix derivation show for: {path}")
        result = subprocess.run(
            ['nix', 'derivation', 'show', path],
            capture_output=True,
            text=True,
            check=True
        )
        deriv_json = json.loads(result.stdout)
        debug_print("Successfully parsed derivation JSON")
        return rfc8785.dumps(deriv_json)
    except Exception as e:
        debug_print(f"Error in get_canonical_derivation: {str(e)}")
        raise

def get_content_hash(drv_path):
    """Get content hash for a derivation"""
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', drv_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error getting hash for {drv_path}: {e.stderr}")

def get_output_hash(path):
    """Get content hash of the built output"""
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error getting output hash for {path}: {e.stderr}")

def compute_sha256_base64(data: bytes):
    """Compute SHA-256 hash and return URL-safe base64 encoded"""
    debug_print(f"Input type: {type(data)}")
    debug_print(f"Input data: {data}...")
    hash_bytes = hashlib.sha256(data).digest()
    result = base64.urlsafe_b64encode(hash_bytes).decode('ascii').rstrip('=')
    debug_print(f"Computed hash: {result}")
    return result

def compute_derivation_input_hash(drv_path: str) -> str:
    """
    Compute the input hash for a derivation path.
    This is the central function that should be used by both signing and verification.
    """
    canonical = get_canonical_derivation(drv_path)
    return compute_sha256_base64(canonical)