import sys
import os
import click
import traceback
import subprocess
from pathlib import Path
from . import (
    get_output_path,
    get_output_hash,
    create_trace_signature,
    parse_nix_key_file,
    upload_signature,
    verify_signatures
)
from .utils import compute_derivation_input_hash, debug_print

def resolve_flake_to_drv(flake_ref: str) -> str:
    """
    Resolve a flake reference to a derivation path
    Example: nixpkgs#hello -> /nix/store/...drv
    """
    try:
        result = subprocess.run(
            ['nix', 'eval', '--raw', f'{flake_ref}.drvPath'],
            capture_output=True,
            text=True,
            check=True
        )
        drv_path = result.stdout.strip()
        debug_print(f"Resolved {flake_ref} to {drv_path}")
        return drv_path
    except subprocess.CalledProcessError as e:
        raise click.BadParameter(f"Failed to resolve flake reference: {e.stderr}")

def is_derivation_path(path: str) -> bool:
    """Check if the given path looks like a derivation path"""
    return path.startswith("/nix/store/") and path.endswith(".drv")

def is_flake_reference(ref: str) -> bool:
    """Check if the given string looks like a flake reference"""
    return "#" in ref

def read_public_key(key_path: str) -> str:
    """Read and validate a public key file"""
    try:
        with open(key_path, 'r') as f:
            key = f.read().strip()
            if ':' not in key:
                raise click.BadParameter(f"Invalid public key format in {key_path}")
            return key
    except FileNotFoundError:
        raise click.BadParameter(f"Public key file not found: {key_path}")
    except Exception as e:
        raise click.BadParameter(f"Error reading public key file {key_path}: {str(e)}")

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
    try:
        private_key = parse_nix_key_file(secret_key_file[0])
        input_hash = compute_derivation_input_hash(drv_path)  # Use central function

        output_path = get_output_path(drv_path)
        output_hash = get_output_hash(output_path)

        jws_token = create_trace_signature(input_hash, output_hash, private_key)
        print(jws_token)

        upload_signature(to, input_hash, jws_token)
    except Exception as e:
        debug_print(f"Error in sign command: {str(e)}")
        traceback.print_exc(file=sys.stderr)
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('target', required=True)
@click.option('--cache', required=False, multiple=True,
              help='URL of signature cache to query (can be specified multiple times)')
@click.option('--trusted-key', required=True, multiple=True, type=click.Path(exists=True),
              help='Path to trusted public key file (can be specified multiple times)')
def verify(target, cache, trusted_key):
    """
    Verify signatures for a derivation or flake reference

    TARGET can be either:
    - A derivation path (/nix/store/....drv)
    - A flake reference (nixpkgs#hello)

    The type will be automatically detected based on the format.

    You must specify at least one cache to query for signatures and at least
    one trusted public key for verification.

    Examples:
        trace-signatures verify \\
            --cache s3://binary-cache \\
            --cache s3://backup-cache \\
            --trusted-key ./keys/builder1.public \\
            --trusted-key ./keys/builder2.public \\
            nixpkgs#hello

        trace-signatures verify \\
            --cache s3://binary-cache \\
            --trusted-key ./keys/trusted.public \\
            /nix/store/xxx.drv
    """
    try:
        # Read and validate trusted keys
        trusted_keys = set()
        for key_path in trusted_key:
            key = read_public_key(key_path)
            trusted_keys.add(key)
            debug_print(f"Added trusted key from {key_path}")

        # Convert target to derivation path if needed
        if is_derivation_path(target):
            debug_print(f"Detected derivation path: {target}")
            if not os.path.exists(target):
                raise click.BadParameter(f"Derivation file does not exist: {target}")
            drv_path = target
        elif is_flake_reference(target):
            debug_print(f"Detected flake reference: {target}")
            drv_path = resolve_flake_to_drv(target)
        else:
            raise click.BadParameter(
                "Target must be either a derivation path (/nix/store/....drv) "
                "or a flake reference (e.g., nixpkgs#hello)"
            )

        # Run verification
        success = verify_signatures(drv_path, caches=list(cache), trusted_keys=trusted_keys)

        if success:
            click.echo("Verification successful!")
            sys.exit(0)
        else:
            click.echo("Verification failed!", err=True)
            sys.exit(1)

    except Exception as e:
        debug_print(f"Error in verify command: {str(e)}")
        traceback.print_exc(file=sys.stderr)
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

def main():
    """Entry point for the script"""
    debug_print("Script started")
    debug_print(f"Args: {sys.argv}")
    debug_print(f"Working directory: {os.getcwd()}")

    try:
        cli.main(prog_name='trace-signatures', standalone_mode=False)
    except click.exceptions.ClickException as e:
        debug_print(f"Click exception: {str(e)}")
        e.show()
        sys.exit(e.exit_code)
    except Exception as e:
        debug_print(f"Fatal error: {str(e)}")
        traceback.print_exc(file=sys.stderr)
        click.echo(f"Fatal error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()