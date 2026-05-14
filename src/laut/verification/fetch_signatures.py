from functools import lru_cache
from pathlib import Path
import json
from typing import Iterable, Optional, List
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from loguru import logger

from laut.storage import parse_http_cache_url
from laut.verification.verify_signatures import verify_resolved_trace_signature
from laut.config import config
import jwt


def fetch_resolved_trace_signature(cache_url, input_hash: str) -> Optional[str]:
    """Fetch signature from HTTP binary cache. Returns content or None on 404."""
    try:
        base_url = parse_http_cache_url(cache_url)
        url = f"{base_url}/traces/{input_hash}"
        req = Request(url, method='GET')
        response = urlopen(req)
        content = response.read()
    except HTTPError as err:
        if err.code == 404:
            logger.debug(f"no signatures found at traces/{input_hash}")
            return None
        raise
    return content


@lru_cache(maxsize=None)
def fetch_resolved_trace_signatures(input_hash: str) -> List[dict]:
    """Fetch and parse signatures from all configured caches"""
    all_signatures = []
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
    valid_signature_data_list = []
    for key in config.trusted_keys:
        for signature in all_signatures:
            valid_signature_data = verify_resolved_trace_signature(key.key_bytes, signature, input_hash)
            if valid_signature_data:
                header = jwt.get_unverified_header(signature)
                if 'kid' not in header:
                    logger.warning("signature missing kid in header, skipping")
                    continue

                kid = header['kid']
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
