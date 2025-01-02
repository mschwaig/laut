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

        canonical = get_canonical_derivation(drv_path)
        deriv_json = json.loads(canonical.decode('utf-8'))
        logger.debug(f"Derivation JSON structure: {json.dumps(deriv_json, indent=2)}")

        drv_data = deriv_json[drv_path]
        if 'outputs' in drv_data and 'out' in drv_data['outputs']:
            output_data = drv_data['outputs']['out']
            if isinstance(output_data, dict) and 'path' in output_data:
                logger.debug(f"Found input-addressed output path: {output_data['path']}")
                return output_data['path']

        raise ValueError("Could not determine output path")
    except Exception:
        logger.exception(f"error getting output path")
        raise

def get_derivation(path):
    """Get Nix derivation data as dict"""
    try:
        logger.debug(f"Running nix derivation show for: {path}")
        result = subprocess.run(
            ['nix', 'derivation', 'show', path],
            capture_output=True,
            text=True,
            check=True
        )
        drv_dict = json.loads(result.stdout)
        logger.debug("Successfully parsed derivation JSON")
        return drv_dict
    except Exception as e:
        logger.exception("error in get_canonical_derivation")
        raise