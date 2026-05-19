from cryptography.hazmat.primitives.asymmetric import ed25519

from lautr import ed25519_thumbprint


def get_ed25519_thumbprint(public_key: ed25519.Ed25519PublicKey) -> str:
    return ed25519_thumbprint(public_key.public_bytes_raw())
