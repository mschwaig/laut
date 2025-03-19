import sys
import os
import click
import subprocess

from .verification.verification import verify_tree_from_drv_path
from .nix.keyfiles import parse_nix_public_key
from .signing import sign_and_upload
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)
from .verification.trust_model import TrustedKey
from loguru import logger

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
        logger.debug(f"Resolved {flake_ref} to {drv_path}")
        return drv_path
    except subprocess.CalledProcessError as e:
        raise click.BadParameter(f"Failed to resolve flake reference: {e.stderr}")

def is_derivation_path(path: str) -> bool:
    """Check if the given path looks like a derivation path"""
    return path.startswith("/nix/store/") and path.endswith(".drv")

def is_flake_reference(ref: str) -> bool:
    """Check if the given string looks like a flake reference"""
    return "#" in ref

def read_public_key(key_path: str) -> TrustedKey:
    """Read and validate a public key file"""
    try:
        return parse_nix_public_key(key_path)
    except Exception as e:
        raise click.BadParameter(f"Error reading public key file {key_path}: {str(e)}")

@click.group()
def cli():
    """Nix build trace signature tool"""
    logger.info("CLI group initialized")
    pass

@cli.command()
@click.argument('drv-path', type=click.Path(exists=True))
@click.option('--secret-key-file', required=True, type=click.Path(exists=True),
              help='Path to the secret key file', multiple=True)
@click.option('--to', required=True,
              help='URL of the target store (e.g., s3://bucket-name)')
@click.option('--out-paths', help='Comma-separated list of output paths (default: check $OUT_PATHS env var)',
              default=None)
def sign(drv_path, secret_key_file, to, out_paths):
    """Sign a derivation and upload the signature"""
    try:
        # Get output paths
        if out_paths is None:
            out_paths = os.environ.get('OUT_PATHS', '')
        paths_list = [p for p in out_paths.split(',') if p]
        sign_and_upload(drv_path, secret_key_file, to, paths_list)
    except Exception as e:
        logger.exception(f"Error in sign command: {str(e)}")
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('target', required=True)
@click.option('--cache', required=False, multiple=True,
              help='URL of signature cache to query (can be specified multiple times)')
@click.option('--trusted-key', required=False, multiple=True, type=click.Path(exists=True),
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
        laut verify \\
            --cache s3://binary-cache \\
            --cache s3://backup-cache \\
            --trusted-key ./keys/builder1.public \\
            --trusted-key ./keys/builder2.public \\
            nixpkgs#hello

        laut verify \\
            --cache s3://binary-cache \\
            --trusted-key ./keys/trusted.public \\
            /nix/store/xxx.drv
    """
    try:
        # Read and validate trusted keys
        trusted_keys = {}  # Dict[str, Ed25519PublicKey]
        for key_path in trusted_keys:
            name, public_key = read_public_key(key_path)
            trusted_keys[name] = public_key
            logger.debug(f"Added trusted key from {key_path}")

        # Convert target to derivation path if needed
        if is_derivation_path(target):
            logger.debug(f"Detected derivation path: {target}")
            if not os.path.exists(target):
                raise click.BadParameter(f"Derivation file does not exist: {target}")
            drv_path = target
        elif is_flake_reference(target):
            logger.debug(f"Detected flake reference: {target}")
            drv_path = resolve_flake_to_drv(target)
        else:
            raise click.BadParameter(
                "Target must be either a derivation path (/nix/store/....drv) "
                "or a flake reference (e.g., nixpkgs#hello)"
            )

        # TODO: pass caches and trust model as parameter
        success = verify_tree_from_drv_path(drv_path)

        if success:
            click.echo("Verification successful!")
            sys.exit(0)
        else:
            click.echo("Verification failed!", err=True)
            sys.exit(1)

    except Exception as e:
        logger.exception(f"Error in verify command.")
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

def main():
    """Entry point for the script"""
    logger.debug("Script started")
    logger.debug(f"Args: {sys.argv}")
    logger.debug(f"Working directory: {os.getcwd()}")

    try:
        cli.main(prog_name='laut', standalone_mode=False)
    except click.exceptions.ClickException as e:
        logger.exception(f"Click exception.")
        sys.exit(e.exit_code)
    except Exception as e:
        logger.exception(f"Fatal Error")
        click.echo(f"Fatal error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
