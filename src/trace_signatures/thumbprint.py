from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

def get_ed25519_thumbprint(public_key: ed25519.Ed25519PublicKey) -> str:
    # Get the raw bytes in DER format
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Create SHA-256 hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw_bytes)
    thumbprint = digest.finalize()
    
    # Convert to hex string
    return thumbprint.hex()