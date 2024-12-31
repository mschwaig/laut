import jwt
from typing import Dict
from .storage import upload_signature
from .signing import create_trace_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from .utils import (
    get_output_path,
    get_output_hash,
    compute_derivation_input_hash,
    parse_nix_private_key,
)
from loguru import logger


def sign_and_upload(drv_path, secret_key_file, to, out_paths):
    # Get output names from derivation
    result = subprocess.run(
        ['nix', 'derivation', 'show', drv_path],
        capture_output=True,
        text=True,
        check=True
    )
    deriv_json = json.loads(result.stdout)
    output_names = list(deriv_json[drv_path].get("outputs", {}).keys())
    logger.debug(f"Output names from derivation: {output_names}")

    # Get output paths
    if out_paths is None:
        out_paths = os.environ.get('OUT_PATHS', '')
    paths = [p for p in out_paths.split(',') if p]

    if not paths:
        logger.debug("No output paths provided, using get_output_path()")
        paths = [get_output_path(drv_path)]

    logger.debug(f"Output paths: {paths}")

    # Map output paths to their names using path suffixes
    output_hashes = {}
    for path in paths:
        # Extract the output name from path suffix
        for name in output_names:
            if path.endswith(f"-{name}") or (name == "out" and not any(path.endswith(f"-{n}") for n in output_names)):
                output_hashes[name] = get_output_hash(path)
                break
        else:
            logger.error(f"Could not determine output name for path: {path}")
            raise ValueError(f"Could not map path to output name: {path}")

    logger.debug(f"Output name to hash mapping: {output_hashes}")

    # Read key and create signature
    with open(secret_key_file[0], 'r') as f:
        content = f.read().strip()
    key_name = content.split(':', 1)[0]
    private_key = parse_nix_private_key(secret_key_file[0])

    input_hash = compute_derivation_input_hash(drv_path)
    jws_token = create_trace_signature(input_hash, output_hashes, private_key, key_name)
    logger.debug(f"{jws_token}")

    upload_signature(to, input_hash, jws_token)

def create_trace_signature(input_hash: str, output_hashes: Dict[str, str], 
                         private_key: Ed25519PrivateKey, key_name: str) -> str:
    """
    Create a JWS signature for outputs

    Args:
        input_hash: The input hash of the derivation
        output_hashes: Dictionary mapping output names to their hashes
        private_key: Ed25519 private key for signing
        key_name: Name of the signing key

    Returns:
        str: The JWS signature token
    """
    headers = {
        "alg": "EdDSA",
        "type": "ntrace",
        "v": "1",
        "kid": key_name
    }

    logger.debug(f"Creating signature for input hash {input_hash} with outputs {output_hashes}")

    payload = {
        "in": input_hash,
        "out": output_hashes,
        "builder": {
            "rebuild": "1",
        }
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=headers
    )