import subprocess
import json
import sys
import rfc8785
import hashlib
import base64
import jwt
import boto3
import click
import traceback
import botocore
from botocore.config import Config
from urllib.parse import urlparse
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def debug_print(msg):
    """Print debug message to stderr"""
    print(f"DEBUG: {msg}", file=sys.stderr)

def get_output_path(drv_path):
    """
    Get the output path for a derivation, handling both input-addressed and
    content-addressed derivations.
    """
    debug_print(f"Getting output path for derivation: {drv_path}")
    try:
        # First try nix path-info with ^* to handle CA derivations
        result = subprocess.run(
            ['nix', 'path-info', f'{drv_path}^*'],
            capture_output=True,
            text=True,
            check=True
        )
        outputs = result.stdout.strip().split('\n')
        if outputs and outputs[0]:
            debug_print(f"Found CA derivation output: {outputs[0]}")
            return outputs[0]

        # If that fails (no outputs), try getting it from the derivation
        debug_print("No CA outputs found, trying derivation JSON")
        canonical = get_canonical_derivation(drv_path)
        deriv_json = json.loads(canonical.decode('utf-8'))
        debug_print(f"Derivation JSON structure: {json.dumps(deriv_json, indent=2)}")

        drv_data = deriv_json[drv_path]
        if 'outputs' in drv_data and 'out' in drv_data['outputs']:
            output_data = drv_data['outputs']['out']
            if isinstance(output_data, dict) and 'path' in output_data:
                debug_print(f"Found input-addressed output path: {output_data['path']}")
                return output_data['path']

        raise ValueError("Could not determine output path")

    except subprocess.CalledProcessError as e:
        debug_print(f"Error running nix path-info: {e.stderr}")
        raise
    except Exception as e:
        debug_print(f"Error getting output path: {str(e)}")
        raise

def get_s3_client(store_url):
    """
    Create an S3 client from the store URL and environment credentials
    """
    debug_print(f"Creating S3 client for URL: {store_url}")
    try:
        parsed_url = urlparse(store_url)
        if not parsed_url.scheme.startswith('s3'):
            raise ValueError(f"Unsupported store URL scheme: {parsed_url.scheme}")

        # Get bucket name - everything between s3:// and first ? or /
        bucket = parsed_url.path.split('?')[0].strip('/')
        if not bucket:
            bucket = parsed_url.netloc.split('?')[0]
        debug_print(f"Extracted bucket name: {bucket}")

        # Parse query parameters
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed_url.query)
        debug_print(f"URL query parameters: {query_params}")

        # Get endpoint URL from the parameters
        endpoint_url = query_params.get('endpoint', [None])[0]
        if endpoint_url:
            debug_print(f"Using endpoint URL: {endpoint_url}")
        else:
            debug_print("No endpoint URL specified, using default S3 endpoint")

        # Create S3 client with path-style addressing
        config = Config(s3={'addressing_style': 'path'})
        return {
            'client': boto3.client(
                's3',
                endpoint_url=endpoint_url,
                config=config
            ),
            'bucket': bucket
        }

    except Exception as e:
        debug_print(f"Error creating S3 client: {str(e)}")
        raise

def get_existing_signatures(s3_client, bucket: str, key: str):
    """
    Get existing signatures from S3, returns None if the object doesn't exist
    """
    try:
        debug_print(f"Fetching existing signatures from {bucket}/{key}")
        response = s3_client.get_object(
            Bucket=bucket,
            Key=key
        )
        content = json.loads(response['Body'].read())
        etag = response['ETag'].strip('"')  # Remove quotes from ETag
        debug_print(f"Found existing signatures with ETag: {etag}")
        return content, etag
    except botocore.exceptions.ClientError as err:
        if err.response['Error']['Code'] == 'NoSuchKey':
            debug_print("No existing signatures found")
            return None, None
        else:
            debug_print(f"Unexpected error getting signatures: {err.response}")
            raise
    except Exception as e:
        debug_print(f"Error fetching existing signatures: {str(e)}")
        raise

def upload_signature(store_url, input_hash, signature):
    """
    Upload the signature to S3-compatible storage using ETag for atomic updates
    """
    try:
        debug_print(f"Uploading signature for input hash: {input_hash}")
        s3_info = get_s3_client(store_url)
        s3_client = s3_info['client']
        bucket = s3_info['bucket']
        key = f"traces/{input_hash}"

        max_retries = 5
        retry_count = 0

        while retry_count < max_retries:
            try:
                # Get existing content and ETag
                existing_content, etag = get_existing_signatures(s3_client, bucket, key)

                if existing_content is None:
                    # No existing signatures, create new file
                    new_content = {
                        "signatures": [signature]
                    }
                    debug_print("Creating new signatures file")
                    s3_client.put_object(
                        Bucket=bucket,
                        Key=key,
                        Body=json.dumps(new_content),
                        ContentType='application/json'
                    )
                    debug_print("Upload successful")
                    break
                else:
                    # Append to existing signatures if not already present
                    if signature not in existing_content["signatures"]:
                        new_content = {
                            "signatures": existing_content["signatures"] + [signature]
                        }
                        debug_print("Updating existing signatures file")
                        try:
                            # Use the correct header for conditional put
                            s3_client.put_object(
                                Bucket=bucket,
                                Key=key,
                                Body=json.dumps(new_content),
                                ContentType='application/json',
                                Metadata={'If-Match': etag}
                            )
                            debug_print("Update successful")
                            break
                        except botocore.exceptions.ClientError as err:
                            if err.response['Error']['Code'] in ['PreconditionFailed', 'InvalidRequest']:
                                # ETag mismatch, retry
                                retry_count += 1
                                debug_print(f"ETag mismatch, retrying ({retry_count}/{max_retries})")
                                if retry_count >= max_retries:
                                    raise Exception("Max retries exceeded while trying to update signatures")
                                continue
                            else:
                                debug_print(f"Unexpected error during conditional put: {err.response}")
                                raise
                    else:
                        debug_print("Signature already exists, skipping upload")
                        break

            except Exception as e:
                if retry_count >= max_retries:
                    debug_print(f"Failed after {max_retries} attempts")
                    raise
                debug_print(f"Error during attempt {retry_count + 1}: {str(e)}")
                retry_count += 1
                continue

    except Exception as e:
        debug_print(f"Error uploading signature: {str(e)}")
        raise

def get_canonical_derivation(path):
    """
    Get a canonicalized JSON representation of a Nix derivation.
    """
    try:
        debug_print(f"Running nix derivation show for: {path}")
        result = subprocess.run(
            ['nix', 'derivation', 'show', path],
            capture_output=True,
            text=True,
            check=True
        )

        deriv_json = json.loads(result.stdout)
        debug_print("Successfully parsed derivation JSON")
        return rfc8785.dumps(deriv_json)

    except subprocess.CalledProcessError as e:
        debug_print(f"Error running 'nix derivation show': {e.stderr}")
        raise
    except json.JSONDecodeError as e:
        debug_print(f"Error parsing derivation JSON: {e}")
        raise

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
    """Compute SHA-256 hash and return URL-safe base64 encoded"""
    hash_bytes = hashlib.sha256(data).digest()
    # Use URL-safe base64 encoding without padding
    return base64.urlsafe_b64encode(hash_bytes).decode('ascii').rstrip('=')

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
        "in": input_hash,  # Already URL-safe from compute_sha256_base64
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
    debug_print("CLI group initialized")
    pass

@cli.command()
@click.argument('drv-path', type=click.Path(exists=True))
@click.option('--secret-key-file', required=True, type=click.Path(exists=True),
              help='Path to the secret key file', multiple=True)
@click.option('--to', required=True,
              help='URL of the target store (e.g., s3://bucket-name)')
def sign(drv_path, secret_key_file, to):
    """Sign a derivation and upload the signature"""
    debug_print(f"Sign command called with:")
    debug_print(f"  drv_path: {drv_path}")
    debug_print(f"  secret_key_file: {secret_key_file}")
    debug_print(f"  to: {to}")

    try:
        debug_print("Parsing private key file")
        private_key = parse_nix_key_file(secret_key_file[0])

        debug_print("Getting canonical derivation")
        canonical = get_canonical_derivation(drv_path)
        debug_print("Parsing JSON")
        initial_json = json.loads(canonical.decode('utf-8'))

        debug_print("Resolving dependencies")
        resolved_json = resolve_dependencies(initial_json)

        debug_print("Canonicalizing resolved derivation")
        resolved_canonical = rfc8785.dumps(resolved_json)

        debug_print("Computing input hash")
        input_hash = compute_sha256_base64(resolved_canonical)

        debug_print("Getting output path")
        output_path = get_output_path(drv_path)
        debug_print(f"Found output path: {output_path}")

        debug_print("Getting output hash")
        output_hash = get_output_hash(output_path)

        debug_print("Creating JWS token")
        jws_token = create_trace_signature(input_hash, output_hash, private_key)

        debug_print("Printing signature")
        print(jws_token)

        debug_print("Uploading signature")
        upload_signature(to, input_hash, jws_token)

    except Exception as e:
        debug_print("Exception in sign command:")
        debug_print(f"Error type: {type(e).__name__}")
        debug_print(f"Error message: {str(e)}")
        debug_print("Traceback:")
        traceback.print_exc(file=sys.stderr)
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('drv-path', type=click.Path(exists=True))
def verify(drv_path):
    """Verify signatures for a derivation (placeholder for future implementation)"""
    debug_print("Verify command called (not implemented)")
    click.echo("Verification not yet implemented")
    sys.exit(1)

def main():
    """Entry point for the script"""
    debug_print("Script started")
    debug_print(f"Args: {sys.argv}")
    debug_print(f"Working directory: {os.getcwd()}")
    debug_print(f"Python version: {sys.version}")

    try:
        debug_print("Invoking Click CLI")
        cli.main(prog_name='trace-signatures.py', standalone_mode=False)
    except click.exceptions.ClickException as e:
        debug_print(f"Click exception: {str(e)}")
        debug_print(f"Parameters: {e.ctx.params if e.ctx else 'No context'}")
        e.show()
        sys.exit(e.exit_code)
    except Exception as e:
        debug_print("Exception in main:")
        debug_print(f"Error type: {type(e).__name__}")
        debug_print(f"Error message: {str(e)}")
        debug_print("Traceback:")
        traceback.print_exc(file=sys.stderr)
        click.echo(f"Fatal error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    debug_print("Starting from __main__")
    main()
