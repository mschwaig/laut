from typing import Dict, Optional, List

import jwt
from ..thumbprint import get_ed25519_thumbprint

from ..storage import get_s3_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)
from loguru import logger

def shorthand(signature):
    return signature.split(".", 2)[2]


def verify_signature_payload(key: Ed25519PublicKey, signature: str) -> Optional[dict]:
    """Verify a JWS signature against trusted keys"""
    try:

        thumbprint = get_ed25519_thumbprint(key)
        # Extract header without verification to get key ID
        header = jwt.get_unverified_header(signature)
        if 'kid' not in header:
            logger.warning("no key ID in signature header")
            return None

        kid = header['kid']
        key_name, received_thumbprint_head = kid.split(':', 1)
        key_thumbprint_head = get_ed25519_thumbprint(key)[:8]
        if received_thumbprint_head != key_thumbprint_head:
            logger.info(f"claims signed with {received_thumbprint_head} and not {key_thumbprint_head}")
            return None

        try:
            payload = jwt.decode(
                signature,
                key=key,
                algorithms=["EdDSA"]
            )
            logger.info(f"Signature {shorthand(signature)} is valid.")
            return payload
        except jwt.InvalidSignatureError:
            logger.exception(f"invalid signature {shorthand(signature)} for key {key_name}")
            return None
        except Exception:
            logger.exception(f"Error verifying signature {shorthand(signature)} with key {key_name}")
            return None

    except Exception:
        logger.exception(f"error verifying signature")
        return None

def verify_resolved_trace_signature(key_bytes: bytes, signature: str, input_hash: str) -> Optional[Dict[str, str]]:
    """
    Verify signatures and collect valid output hashes

    Args:
        signatures: List of JWS signature tokens to verify
        input_hash: Expected input hash to validate against

    Returns:
        List[Dict[str, str]]: List of valid output hash mappings
    """
    key = Ed25519PublicKey.from_public_bytes(key_bytes)

    payload = verify_signature_payload(key, signature)
    if payload and payload.get("in") == input_hash:
        output_hashes = payload.get("out")
        if isinstance(output_hashes, dict):
            logger.debug(f"found valid output hash mapping")
            return payload

        else:
            logger.error(f"invalid signature payload: {payload}")
            return None
    else:
        return None

