from functools import lru_cache
from pathlib import Path
import json
from typing import Iterable, Optional, List

from loguru import logger

from laut.storage import get_s3_client
from laut.verification.verify_signatures import verify_resolved_trace_signature
from laut.config import config
import jwt

def fetch_resolved_trace_signature_from_s3_bucket(cache_url, input_hash: str) -> Optional[str]:
    try:
        s3_info = get_s3_client(cache_url, anon=True)
        s3_client = s3_info['client']
        bucket = s3_info['bucket']
        key = f"traces/{input_hash}"
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read()
    except s3_client.exceptions.NoSuchKey:
        logger.exception(f"no signatures found at {key}")
        return None
    return content

@lru_cache(maxsize=None)
def fetch_resolved_trace_signatures(input_hash: str) -> List[dict]:
    """Fetch and parse signatures from all configured caches"""
    all_signatures = []
    for cache_url in config.cache_urls:
        try:
            content = fetch_resolved_trace_signature_from_s3_bucket(cache_url, input_hash)
            if content:
                parsed_content = json.loads(content)
                all_signatures.extend(parsed_content.get("signatures", []))
        except Exception:
            logger.exception(f"error fetching signatures from {cache_url}")
            continue
    logger.debug(f"{len(all_signatures)} signatures found for input hash {input_hash}.")

    return all_signatures

def verify_signatures(input_hash, all_signatures):
    valid_signature_data_list = []
    for key in config.trusted_keys:
        for signature in all_signatures:
            valid_signature_data = verify_resolved_trace_signature(key.key_bytes, signature, input_hash)
            if valid_signature_data:
                # Extract full kid from JWT header
                # TODO: Eventually require full public key and use kid for display only
                header = jwt.get_unverified_header(signature)
                if 'kid' not in header:
                    logger.warning("signature missing kid in header, skipping")
                    continue

                kid = header['kid']
                # Return tuple of (signature_data, signing_key)
                valid_signature_data_list.append((valid_signature_data, kid))

    logger.debug(f"found {len(valid_signature_data_list)} valid output hash mappings")
    return valid_signature_data_list

def fetch_and_verify_signatures(input_hash):
    all_signatures = fetch_resolved_trace_signatures(input_hash)
    valid_signatures = verify_signatures(input_hash, all_signatures)
    return valid_signatures

def fetch_preimage_from_index(drv_name) -> Iterable[tuple[str, str]]:
    with open(config.preimage_index) as f:
        index = json.load(f)
   
    one_or_many_drv = index[drv_name]
    if isinstance(one_or_many_drv, list):
        for i in one_or_many_drv:
            yield (Path(i["in"]["debug"]["rdrv_path"]).name, i["in"]["debug"]["rdrv_aterm_ca_preimage"])
    else:
        one = one_or_many_drv
        yield (Path(one["in"]["debug"]["rdrv_path"]).name, one["in"]["debug"]["rdrv_aterm_ca_preimage"])
