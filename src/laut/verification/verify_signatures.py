from typing import Dict, Optional, List

import jwt
from ..thumbprint import get_ed25519_thumbprint

from ..storage import get_s3_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)
from loguru import logger

def verify_signature_payload(key: Ed25519PublicKey, signature: str) -> Optional[dict]:
    """Verify a JWS signature against trusted keys"""
    try:

        thumbprint = get_ed25519_thumbprint(key)
        # Extract header without verification to get key ID
        header = jwt.get_unverified_header(signature)
        if 'kid' not in header:
            logger.warning("no key ID in signature header")
            return None

        key_name = header['kid']
        # TODO: find what we want to do about name / thumbprint
        #if key_name != thumbprint:
        #    logger.debug(f"claims signed with different key")
        #    return None

        try:
            # Verify with EdDSA algorithm
            payload = jwt.decode(
                signature,
                key=key,
                algorithms=["EdDSA"]
            )
            logger.debug(f"Signature {signature} is valid.")
            return payload
        except jwt.InvalidSignatureError:
            logger.exception(f"invalid signature for key {key_name}")
            return None
        except Exception:
            logger.exception(f"Error verifying with key {key_name}")
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
    valid_output_hashes = []

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

