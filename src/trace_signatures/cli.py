import sys
import os
import click
import traceback
from . import (
    get_canonical_derivation,
    get_output_path,
    get_output_hash,
    compute_sha256_base64,
    create_trace_signature,
    parse_nix_key_file,
    upload_signature,
    verify_signatures
)
from .utils import debug_print

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
        canonical = get_canonical_derivation(drv_path)
        input_hash = compute_sha256_base64(canonical)
        
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
@click.argument('drv-path', type=click.Path(exists=True))
def verify(drv_path):
    """Verify signatures for a derivation"""
    try:
        verify_signatures(drv_path)
    except NotImplementedError:
        click.echo("Verification not yet implemented")
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
