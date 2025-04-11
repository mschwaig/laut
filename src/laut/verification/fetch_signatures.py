from functools import lru_cache
from pathlib import Path

from laut.verification.verify_signatures import verify_resolved_trace_signature
from ..storage import get_s3_client
import json
from loguru import logger
from typing import Dict, Iterable, Set, Optional, List

from laut.config import config

@lru_cache(maxsize=None)
def fetch_resolved_trace_signatures(input_hash: str) -> List[dict]:
    """Fetch and parse signatures from all configured caches"""
    all_signatures = []
    for cache_url in config.cache_urls:
        try:
            s3_info = get_s3_client(cache_url, anon=True)
            s3_client = s3_info['client']
            bucket = s3_info['bucket']
            key = f"traces/{input_hash}"

            try:
                response = s3_client.get_object(Bucket=bucket, Key=key)
                content = response['Body'].read()
                if content:
                    parsed_content = json.loads(content)
                    all_signatures.extend(parsed_content.get("signatures", []))
            except s3_client.exceptions.NoSuchKey:
                logger.exception(f"no signatures found at {key}")
                continue
        except Exception:
            logger.exception(f"error fetching signatures from {cache_url}")
            continue
    logger.debug(f"{len(all_signatures)} signatures found for input hash {input_hash}: {all_signatures}")

    return all_signatures

def verify_signatures(all_signatures):
    valid_signature_data_list = []
    for key in config.trusted_keys:
        for signature in all_signatures:
            valid_signature_data = verify_resolved_trace_signature(key, signature)
            valid_signature_data_list.append(valid_signature_data)

    logger.debug(f"found {len(valid_signature_data_list)} valid output hash mappings")
    return all_signatures

def fetch_and_verify_signatures(input_hash):
    all_signatures = fetch_resolved_trace_signatures(input_hash)
    valid_signatures = verify_signatures(all_signatures)
    return valid_signatures

def fetch_preimage_from_index(drv_name) -> Iterable[tuple[str, str]]:
    with open(config.preimage_index) as f:
        index = json.load(f)
   
    one_or_many_drv = index[drv_name]
    if one_or_many_drv is list:
        for i in one_or_many_drv:
            yield (Path(i["drv_path"]).name, i["in_preimage"])
    else:
        one = one_or_many_drv
        yield (Path(one["drv_path"]).name, one["in_preimage"])
