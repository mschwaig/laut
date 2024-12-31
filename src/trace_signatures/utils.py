import subprocess
import json
import hashlib
import base64
import rfc8785
from loguru import logger

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, 
    Ed25519PublicKey
)

def get_output_path(drv_path):
    """Get the output path for a derivation"""
    logger.debug(f"Getting output path for derivation: {drv_path}")
    try:
        result = subprocess.run(
            ['nix', 'path-info', f'{drv_path}^*'],
            capture_output=True,
            text=True,
            check=True
        )
        outputs = result.stdout.strip().split('\n')
        if outputs and outputs[0]:
            logger.debug(f"Found CA derivation output: {outputs[0]}")
            return outputs[0]

        canonical = get_canonical_derivation(drv_path)
        deriv_json = json.loads(canonical.decode('utf-8'))
        logger.debug(f"Derivation JSON structure: {json.dumps(deriv_json, indent=2)}")

        drv_data = deriv_json[drv_path]
        if 'outputs' in drv_data and 'out' in drv_data['outputs']:
            output_data = drv_data['outputs']['out']
            if isinstance(output_data, dict) and 'path' in output_data:
                logger.debug(f"Found input-addressed output path: {output_data['path']}")
                return output_data['path']

        raise ValueError("Could not determine output path")
    except Exception:
        logger.exception(f"error getting output path")
        raise

def get_canonical_derivation(path):
    """Get canonicalized JSON representation of a Nix derivation"""
    try:
        logger.debug(f"Running nix derivation show for: {path}")
        result = subprocess.run(
            ['nix', 'derivation', 'show', path],
            capture_output=True,
            text=True,
            check=True
        )
        deriv_json = json.loads(result.stdout)
        logger.debug("Successfully parsed derivation JSON")
        return rfc8785.dumps(deriv_json)
    except Exception as e:
        logger.exception("error in get_canonical_derivation")
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
    logger.debug(f"Input type: {type(data)}")
    logger.debug(f"Input data: {data}...")
    hash_bytes = hashlib.sha256(data).digest()
    result = base64.urlsafe_b64encode(hash_bytes).decode('ascii').rstrip('=')
    logger.debug(f"Computed hash: {result}")
    return result

def compute_derivation_input_hash(drv_path: str) -> str:
    """
    Compute the input hash for a derivation path.
    This is the central function that should be used by both signing and verification.
    """
    canonical = get_canonical_derivation(drv_path)
    return compute_sha256_base64(canonical)

def parse_nix_private_key(key_path: str) -> Ed25519PrivateKey:
    """
    Parse a Nix private signing key file
    
    Args:
        key_path: Path to the private key file
        
    Returns:
        Ed25519PrivateKey: The loaded private key
        
    Raises:
        ValueError: If the key file is invalid
    """
    try:
        with open(key_path, 'r') as f:
            content = f.read().strip()

        name, key_b64 = content.split(':', 1)
        key_bytes = base64.b64decode(key_b64)
        private_key_bytes = key_bytes[:32]  # Ed25519 private keys are 32 bytes
        return Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse private key file {key_path}: {str(e)}")

def parse_nix_public_key(key_path: str) -> tuple[str, Ed25519PublicKey]:
    """
    Parse a Nix public key file
    
    Args:
        key_path: Path to the public key file
        
    Returns:
        tuple[str, Ed25519PublicKey]: The key name and loaded public key
        
    Raises:
        ValueError: If the key file is invalid
    """
    try:
        with open(key_path, 'r') as f:
            content = f.read().strip()

        name, key_b64 = content.split(':', 1)
        key_bytes = base64.b64decode(key_b64)
        
        # Ed25519 public keys are 32 bytes
        if len(key_bytes) != 32:
            raise ValueError("Invalid public key length")
            
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        return name, public_key
    except Exception as e:
        logger.exception("failed to parse public key file {key_path}")
        raise ValueError(f"Failed to parse public key file {key_path}: {str(e)}")
