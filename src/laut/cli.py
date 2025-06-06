import sys
import os
from typing import List
import subprocess

import click
from loguru import logger

from laut.config import config
from laut.nix.keyfiles import parse_nix_public_key
from laut.signing import (
    sign_impl,
    sign_and_upload_impl
)
from laut.nix.keyfiles import TrustedKey
from laut.thumbprint import get_ed25519_thumbprint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from laut import build_config

if not build_config.sign_only:
    from laut.verification.verification import verify_tree_from_drv_path

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
    """Read and validate a public key file, including thumbprint"""
    try:
        # Parse the key from file
        trusted_key = parse_nix_public_key(key_path)

        # Create an Ed25519PublicKey from the raw bytes
        ed25519_key = Ed25519PublicKey.from_public_bytes(trusted_key.key_bytes)

        # Calculate the thumbprint
        thumbprint = get_ed25519_thumbprint(ed25519_key)

        # Create the full key ID in the same format as signing
        key_id = f"{trusted_key.name}:{thumbprint[:16]}"

        # Return a new TrustedKey with the updated name
        return TrustedKey(name=key_id, key_bytes=trusted_key.key_bytes)
    except Exception as e:
        raise click.BadParameter(f"Error reading public key file {key_path}: {str(e)}")

@click.group()
@click.option('--debug/--no-debug', default=False)
@click.pass_context
def cli(ctx: click.Context, debug: bool):
    config.debug = debug
    """Nix build trace signature tool"""
    logger.info("CLI group initialized")

    if build_config.sign_only and ctx.invoked_subcommand and (not ctx.invoked_subcommand in [ "sign", "sign-and-upload" ]):
        logger.error(f"invoked subcommand '{ctx.invoked_subcommand}' unavailable in 'sign-only' configuration of laut")
        ctx.exit(1)
    pass


@cli.command()
@click.argument('drv-path', type=click.Path(exists=True))
@click.option('--secret-key-file', required=True, type=click.Path(exists=True),
              help='Path to the secret key file', multiple=True)
@click.option('--out-paths', help='Comma-separated list of output paths (default: check $OUT_PATHS env var)',
              default=None)
def sign(drv_path, secret_key_file, out_paths):
    """Sign a derivation"""
    try:
        if out_paths is None:
            out_paths = os.environ.get('OUT_PATHS')

        # TODO: make sure that drv_path and out_paths are not None and not .isspace()
        # TODO: eliminate duplication in argument handling between sign and sign-and-upload as much as possible
        paths_list = out_paths.split(" ")
        result = sign_impl(drv_path, secret_key_file, paths_list)
        if result:
            input_hash, jws_token = result
            logger.debug("printing signature to stdout")
            # result is the produced signature
            sys.stdout.write(f"{jws_token}\n")
        else:
            # there is no result
            # because the passed derivation
            # has not been resolved yet
            sys.exit(117)
    except Exception as e:
        logger.exception(f"Error in sign command: {str(e)}")
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('drv-path', type=click.Path(exists=True))
@click.option('--secret-key-file', required=True, type=click.Path(exists=True),
              help='Path to the secret key file', multiple=True)
@click.option('--to', required=True,
              help='URL of the target store (e.g., s3://bucket-name)')
@click.option('--out-paths', help='Comma-separated list of output paths (default: check $OUT_PATHS env var)',
              default=None)
def sign_and_upload(drv_path, secret_key_file, to, out_paths):
    """Sign a derivation and upload the signature"""
    try:
        if out_paths is None:
            out_paths = os.environ.get('OUT_PATHS')

        # TODO: make sure that drv_path and out_paths are not None and not .isspace()
        # TODO: eliminate duplication in argument handling between sign and sign-and-upload as much as possible
        paths_list = out_paths.split(" ")
        sign_and_upload_impl(drv_path, secret_key_file, to, paths_list)
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
    config.cache_urls = cache
    logger.debug(f"configured cache urls: {config.cache_urls}")

    try:
        # Read and validate trusted keys
        trusted_keys : List[TrustedKey] = []
        for key_path in trusted_key:
            public_key = read_public_key(key_path)
            trusted_keys.append(public_key)
            logger.debug(f"Added trusted key from {key_path}")

        config.trusted_keys = trusted_keys
        logger.debug(f"configured trusted keys: {config.trusted_keys}")

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

        sucessfully_resolved = verify_tree_from_drv_path(drv_path)

        if sucessfully_resolved:
            click.echo(f"successfully resolved {target} to {sucessfully_resolved}")
            sys.exit(0)
        else:
            click.echo(f"failed to resolve {target}", err=True)
            sys.exit(118)

    except Exception as e:
        logger.exception(f"Error in verify command.")
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

def main():
    """Entry point for the script"""
    logger.debug("Script started on {sys.version}")
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
