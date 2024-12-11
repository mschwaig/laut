#! /usr/bin/env -S python3 -u
import subprocess
import json
import sys
import rfc8785
import hashlib
import base64
import jwt
import boto3
import click
from botocore.config import Config
from urllib.parse import urlparse
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def get_s3_client(store_url):
    """
    Create an S3 client from the store URL and environment credentials
    """
    parsed_url = urlparse(store_url)
    if not parsed_url.scheme.startswith('s3'):
        raise ValueError(f"Unsupported store URL scheme: {parsed_url.scheme}")

    # Extract endpoint URL from the store URL
    endpoint_url = f"https://{parsed_url.netloc}"

    # Create S3 client with path-style addressing
    config = Config(s3={'addressing_style': 'path'})
    return boto3.client(
        's3',
        endpoint_url=endpoint_url,
        config=config
    )

def upload_signature(store_url, input_hash, signature):
    """
    Upload the signature to S3-compatible storage
    """
    try:
        s3_client = get_s3_client(store_url)
        parsed_url = urlparse(store_url)
        bucket = parsed_url.path.strip('/')

        # Create the trace content
        trace_content = {
            "signatures": [signature]
        }

        # Upload to traces/<input-hash>
        key = f"traces/{input_hash}"
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(trace_content),
            ContentType='application/json'
        )

    except Exception as e:
        print(f"Error uploading signature: {e}", file=sys.stderr)
        sys.exit(1)

def get_canonical_derivation(path):
    """
    Get a canonicalized JSON representation of a Nix derivation.
    """
    try:
        # Run nix derivation show
        result = subprocess.run(
            ['nix', 'derivation', 'show', path],
            capture_output=True,
            text=True,
            check=True
        )

        # Parse the JSON output
        deriv_json = json.loads(result.stdout)

        # Canonicalize using JCS
        return rfc8785.dumps(deriv_json)

    except subprocess.CalledProcessError as e:
        print(f"Error running 'nix derivation show': {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing derivation JSON: {e}", file=sys.stderr)
        sys.exit(1)

def get_content_hash(drv_path):
    """
    Get the content hash for a derivation using nix-store --query --hash
    """
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', drv_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting hash for {drv_path}: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def resolve_dependencies(deriv_json):
    """
    Resolve all dependencies in a derivation by getting their content hashes
    and incorporating them into inputSrcs.
    """
    # We'll work with the first (and typically only) derivation in the JSON
    drv_path = next(iter(deriv_json))
    drv_data = deriv_json[drv_path]

    # Get existing inputSrcs
    resolved_srcs = list(drv_data.get('inputSrcs', []))

    # Get all input derivations and do not sort since we assume the order is meaningful
    input_drvs = drv_data.get('inputDrvs', {}).keys()

    # Get content hash for each input derivation and add to inputSrcs
    for drv in input_drvs:
        hash_path = get_content_hash(drv)
        resolved_srcs.append(hash_path)

    # Create modified derivation with resolved dependencies
    modified_drv = deriv_json.copy()
    modified_drv[drv_path]['inputSrcs'] = resolved_srcs
    modified_drv[drv_path]['inputDrvs'] = {}

    return modified_drv

def compute_sha256_base64(data):
    """Compute SHA-256 hash and return base64 encoded"""
    hash_bytes = hashlib.sha256(data).digest()
    return base64.b64encode(hash_bytes).decode('ascii')

def get_output_hash(path):
    """Get the content hash of the built output"""
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting output hash for {path}: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def parse_nix_key_file(key_path):
    """
    Parse a Nix signing key file in the format 'name:base64key'
    The key is in libsodium format: 64 bytes (32 byte key + 32 byte salt)
    """
    with open(key_path, 'r') as f:
        content = f.read().strip()

    name, key_b64 = content.split(':', 1)
    key_bytes = base64.b64decode(key_b64)

    # Extract just the private key (first 32 bytes)
    private_key_bytes = key_bytes[:32]

    return Ed25519PrivateKey.from_private_bytes(private_key_bytes)

def create_trace_signature(input_hash: str, output_hash: str, private_key):
    """Create a JWS signature in the specified format"""
    headers = {
        "alg": "EdDSA",
        "type": "ntrace",
        "v": "1"
    }

    payload = {
        "in": input_hash,
        "out": output_hash,
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

@click.group()
def cli():
    """Nix build trace signature tool"""
    pass

@cli.command()
@click.argument('drv-path')
@click.option('--secret-key-file', required=True, multiple=True,
              help='Path to the secret key file')
@click.option('--to', required=True,
              help='URL of the target store (e.g., s3://bucket-name)')
def sign(drv_path, secret_key_file, to):
    """Sign a derivation and upload the signature"""
    try:
        # Parse the first private key file (maintain compatibility with original behavior)
        private_key = parse_nix_key_file(secret_key_file[0])

        # Get initial derivation
        canonical = get_canonical_derivation(drv_path)
        initial_json = json.loads(canonical.decode('utf-8'))

        # Resolve dependencies
        resolved_json = resolve_dependencies(initial_json)

        # Canonicalize the resolved derivation
        resolved_canonical = rfc8785.dumps(resolved_json)

        # Compute final input hash
        input_hash = compute_sha256_base64(resolved_canonical)

        # Get the output path from the derivation
        drv_path_key = next(iter(initial_json))
        output_path = initial_json[drv_path_key]['outputs']['out']['path']

        # Get output hash
        output_hash = get_output_hash(output_path)

        # Create JWS
        jws_token = create_trace_signature(input_hash, output_hash, private_key)

        # Print the signature to stdout
        print(jws_token)

        # Upload signature to S3
        upload_signature(to, input_hash, jws_token)

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('drv-path')
def verify(drv_path):
    """Verify signatures for a derivation (placeholder for future implementation)"""
    click.echo("Verification not yet implemented")
    sys.exit(1)

if __name__ == '__main__':
    cli()