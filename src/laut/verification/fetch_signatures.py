from functools import lru_cache
from pathlib import Path
from ..storage import get_s3_client
import json
from loguru import logger
from typing import Dict, Set, Optional, List

def fetch_ct_signatures_mock(input_hash: str) -> List[dict]:
    """Fetch and parse signatures from local mock cache"""
    all_signatures = []
    signature_file = Path(__file__).parent.parent.parent.parent / "tests" / "traces" / "out4" / "builderA.json"
    try:
        with open(signature_file) as f:
            signature_json = json.load(f)
            all_signatures = [ signature_json[input_hash] ]
            logger.debug(f"{len(all_signatures)} signatures found for input hash {input_hash}: {all_signatures}")
            return all_signatures
    except Exception:
        logger.exception(f"no signatures found for input hash {input_hash}")

    return all_signatures

@lru_cache(maxsize=None)
def fetch_ct_signatures(input_hash: str) -> List[dict]:
    """Fetch and parse signatures from all configured caches"""
    all_signatures = []
    for cache_url in []: # [ "https://cache.nixos.org" ]:
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

#def fetch_dct_signatures(input_hash: UnresolvedInputHash):
#    return