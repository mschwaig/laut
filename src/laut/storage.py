from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json
from loguru import logger


def parse_http_cache_url(store_url):
    """Parse an HTTP binary cache URL and return the base URL.

    Args:
        store_url (str): The HTTP store URL (e.g., http://cache:9000)
    """
    logger.debug(f"Parsing HTTP cache URL: {store_url}")
    parsed_url = urlparse(store_url)
    if parsed_url.scheme not in ('http', 'https'):
        raise ValueError(f"Unsupported store URL scheme: {parsed_url.scheme}")
    # Ensure no trailing slash for clean concatenation
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if parsed_url.path and parsed_url.path != '/':
        base_url += parsed_url.path.rstrip('/')
    return base_url


def get_existing_signatures(base_url, input_hash):
    """Get existing signatures via HTTP GET.

    Returns (json_body, etag) or (None, None) on 404.
    """
    url = f"{base_url}/traces/{input_hash}"
    req = Request(url, method='GET')
    try:
        response = urlopen(req)
        content = json.loads(response.read())
        etag = response.headers.get('ETag', '').strip('"')
        return content, etag
    except HTTPError as err:
        if err.code == 404:
            return None, None
        raise
    except Exception:
        logger.exception("error fetching existing signatures")
        raise


def upload_signature(store_url, input_hash, signature):
    """Upload signature to HTTP cache storage with ETag-based optimistic concurrency."""
    try:
        base_url = parse_http_cache_url(store_url)
        key = input_hash

        max_retries = 5
        retry_count = 0

        while retry_count < max_retries:
            try:
                existing_content, etag = get_existing_signatures(base_url, key)

                if existing_content is None:
                    new_content = {"signatures": [signature]}
                    url = f"{base_url}/traces/{key}"
                    # `If-None-Match: *` makes this a conditional create: if
                    # another builder PUT a signature for the same input hash
                    # between our GET and our PUT, the server returns 412 and
                    # we fall through to the retry loop, which GETs the now-
                    # populated cache and appends our signature with If-Match.
                    req = Request(
                        url,
                        data=json.dumps(new_content).encode('utf-8'),
                        method='PUT',
                        headers={
                            'Content-Type': 'application/json',
                            'If-None-Match': '*',
                        }
                    )
                    try:
                        urlopen(req)
                    except HTTPError as err:
                        if err.code not in (412, 409):
                            raise
                    retry_count += 1
                    continue
                elif signature not in existing_content["signatures"]:
                    new_content = {
                        "signatures": existing_content["signatures"] + [signature]
                    }
                    url = f"{base_url}/traces/{key}"
                    headers = {
                        'Content-Type': 'application/json',
                        'If-Match': f'"{etag}"'
                    }
                    req = Request(
                        url,
                        data=json.dumps(new_content).encode('utf-8'),
                        method='PUT',
                        headers=headers
                    )
                    try:
                        urlopen(req)
                        break
                    except HTTPError as err:
                        if err.code in (412, 409):
                            retry_count += 1
                            if retry_count >= max_retries:
                                raise Exception("Max retries exceeded")
                            continue
                        raise
                else:
                    logger.debug("Signature already exists")
                    break

            except Exception:
                if retry_count >= max_retries:
                    raise
                retry_count += 1
                continue

    except Exception:
        logger.exception("error uploading signature")
        raise
