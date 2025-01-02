import subprocess
import hashlib
import base64
from loguru import logger
from .commands import get_canonical_derivation

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
