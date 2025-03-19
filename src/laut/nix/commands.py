from functools import lru_cache
import subprocess
import json
from loguru import logger

def get_output_path(drv_path):
    """Get the output path for a derivation"""
    logger.debug(f"Getting output path for derivation: {drv_path}")
    try:
        result = subprocess.run(
            ['nix', 'path-info', f'{drv_path}^*'],
            capture_output=True,
            text=True,
            check=True
        )
        outputs = result.stdout.strip().split('\n')
        if outputs and outputs[0]:
            logger.debug(f"Found CA derivation output: {outputs[0]}")
            return outputs[0]

        drv_data = get_derivation(drv_path)
        if 'outputs' in drv_data and 'out' in drv_data['outputs']:
            output_data = drv_data['outputs']['out']
            if isinstance(output_data, dict) and 'path' in output_data:
                logger.debug(f"Found input-addressed output path: {output_data['path']}")
                return output_data['path']

        raise ValueError("Could not determine output path")
    except Exception:
        logger.exception(f"error getting output path")
        raise

@lru_cache(maxsize=None)
def get_derivation(drv_path, recursive: bool):
    """Get Nix derivation data as dict"""
    try:
        logger.debug(f"Running nix derivation show for: {drv_path}")
        if recursive:
            result = subprocess.run(
                ['nix', '--extra-experimental-features', 'nix-command', 'derivation', 'show', '--recursive', drv_path],
                capture_output=True,
                text=True,
                check=True
            )
        else:
            result = subprocess.run(
                ['nix', '--extra-experimental-features', 'nix-command', 'derivation', 'show', drv_path],
                capture_output=True,
                text=True,
                check=True
            )
        drv_dict = json.loads(result.stdout)
        logger.debug("Successfully parsed derivation JSON")
        if recursive:
            return drv_dict
        else:
            return drv_dict[drv_path]
    except Exception as e:
        logger.exception("error in get_derivation")
        raise

def get_output_hash_from_disk(out_path):
    """Get content hash of the built output"""
    # TODO: verify that this is called with an output path
    try:
        result = subprocess.run(
            ['nix-store', '--query', '--hash', out_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error getting output hash for {out_path}: {e.stderr}")

def check_nixos_cache(drv_path: str) -> bool:
    """Check if a derivation exists in the official nixos cache"""
    """TODO: this only works if Nix knows how to build drv_path, so we should think of something else"""
    try:
        result = subprocess.run(
            ['nix', 'path-info', '--store', 'https://cache.nixos.org', drv_path],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        logger.exception("error checking nixos cache")
        return False

def get_from_nixos_cache(drv_path: str) -> bool:
    """Check if a derivation exists in the official nixos cache"""
    try:
        logger.debug(f"Fetching info for {drv_path} from nixos cache")
        result = subprocess.run(
            [
                'nix',
                'path-info',
                '--json',
                '--store', 'https://cache.nixos.org',
                f'{drv_path}^*'
            ],
            capture_output=True,
            text=True,
            check=True
        )

        outputs_info = json.loads(result.stdout)
        logger.debug(f"Raw output info: {json.dumps(outputs_info, indent=2)}")
        return outputs_info
    except Exception:
        logger.exception("error checking nixos cache")
        return False
