import sys
import os
import subprocess

import click
from loguru import logger

from laut.config import config
from laut.signing import (
    sign_impl,
    sign_and_upload_impl
)

from laut import build_config

if not build_config.sign_only:
    from lautr import parse_nix_public_key, verify_tree

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
@click.option('--include-preimage/--no-include-preimage', default=False,
              help='Include the ATerm preimage in the signed JWS debug block. '
                   'For test environments only — production signers should keep '
                   'this off so preimages never leak into shared caches.')
def sign(drv_path, secret_key_file, out_paths, include_preimage):
    """Sign a derivation"""
    config.include_preimage = include_preimage
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
              help='URL of the target store (e.g., http://cache:9000)')
@click.option('--out-paths', help='Comma-separated list of output paths (default: check $OUT_PATHS env var)',
              default=None)
@click.option('--include-preimage/--no-include-preimage', default=False,
              help='Include the ATerm preimage in the signed JWS debug block. '
                   'For test environments only — production signers should keep '
                   'this off so preimages never leak into shared caches.')
def sign_and_upload(drv_path, secret_key_file, to, out_paths, include_preimage):
    """Sign a derivation and upload the signature"""
    config.include_preimage = include_preimage
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
            help='URL of HTTP signature cache to query (can be specified multiple times)')
@click.option('--trusted-key', required=False, multiple=True, type=click.Path(exists=True),
            help='Path to trusted public key file (can be specified multiple times)')
@click.option('--debug-preimage-corpus', required=False, default=None,
            help='Cache URL to scan for signer-side debug preimages. When a '
                 'resolved-input-hash lookup misses, runs difft against any '
                 'preimage with a matching drv-name. Requires the cache to '
                 'expose a GET /traces/ listing endpoint, which most production '
                 'caches will refuse.')
@click.option('--debug-out-dir', required=False, default=None, type=click.Path(),
            help='Directory to drop preimage artifacts into for --debug-preimage-corpus. '
                 'Defaults to a temp dir.')
def verify(target, cache, trusted_key, debug_preimage_corpus, debug_out_dir):
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
            --cache http://cache:9000 \\
            --cache http://backup:9000 \\
            --trusted-key ./keys/builder1.public \\
            --trusted-key ./keys/builder2.public \\
            nixpkgs#hello

        laut verify \\
            --cache http://cache:9000 \\
            --trusted-key ./keys/trusted.public \\
            /nix/store/xxx.drv
    """
    try:
        trusted_keys_raw = []
        for key_path in trusted_key:
            name, key_bytes = parse_nix_public_key(key_path)
            trusted_keys_raw.append((name, bytes(key_bytes)))
            logger.debug(f"Added trusted key from {key_path}")

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

        verified = verify_tree(
            drv_path,
            list(cache),
            trusted_keys_raw,
            False,
            debug_preimage_corpus,
            debug_out_dir,
        )

        if verified:
            click.echo(f"successfully resolved {target} to {verified[0]}")
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
