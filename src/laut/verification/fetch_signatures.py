from functools import lru_cache
from pathlib import Path
import json
from typing import Iterable, Optional, List

from loguru import logger

from laut.config import config
from lautr import (
    fetch_signatures_from_cache,
    parse_http_cache_url,
    verify_resolved_trace_signatures,
)


def fetch_resolved_trace_signature(cache_url, input_hash: str) -> Optional[bytes]:
    """Fetch signature from HTTP binary cache. Returns content or None on 404."""
    base_url = parse_http_cache_url(cache_url)
    content = fetch_signatures_from_cache(base_url, input_hash)
    if content is None:
        logger.debug(f"no signatures found at traces/{input_hash}")
    return content


@lru_cache(maxsize=None)
def fetch_resolved_trace_signatures(input_hash: str) -> List[str]:
    """Fetch and parse signatures from all configured caches"""
    all_signatures: List[str] = []
    for cache_url in config.cache_urls:
        try:
            content = fetch_resolved_trace_signature(cache_url, input_hash)
            if content:
                parsed_content = json.loads(content)
                all_signatures.extend(parsed_content.get("signatures", []))
        except Exception:
            logger.exception(f"error fetching signatures from {cache_url}")
            continue
    logger.debug(f"{len(all_signatures)} signatures found for input hash {input_hash}.")

    return all_signatures


def verify_signatures(input_hash, all_signatures):
    trusted_keys = [(k.name, k.key_bytes) for k in config.trusted_keys]
    results = verify_resolved_trace_signatures(input_hash, all_signatures, trusted_keys)
    valid_signature_data_list = [(json.loads(payload), kid) for payload, kid in results]
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
