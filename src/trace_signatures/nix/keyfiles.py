import base64
from loguru import logger
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, 
    Ed25519PublicKey
)
from ..verification.trust_model import TrustedKey

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

def parse_nix_public_key(key_path: str) -> TrustedKey:
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
        return TrustedKey(name=name, key=public_key)
    except Exception as e:
        logger.exception("failed to parse public key file {key_path}")
        raise ValueError(f"Failed to parse public key file {key_path}: {str(e)}")
