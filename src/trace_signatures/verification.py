import json
import subprocess
from dataclasses import dataclass
from typing import Set, Dict, List
from pathlib import Path
import sys

@dataclass
class DerivationInfo:
    """Information about a derivation and its dependencies"""
    drv_path: str
    input_derivations: Set[str]  # Paths to input derivations
    input_sources: Set[str]      # Paths to source files
    output_paths: Dict[str, str] # Output name -> output path mapping

def get_derivation_info(drv_path: str) -> DerivationInfo:
    """
    Get detailed information about a derivation including all its dependencies
    """
    try:
        # Get the full derivation data using nix derivation show
        result = subprocess.run(
            ['nix', 'derivation', 'show', drv_path],
            capture_output=True,
            text=True,
            check=True
        )

        deriv_json = json.loads(result.stdout)
        if not deriv_json or drv_path not in deriv_json:
            raise ValueError(f"Could not find derivation data for {drv_path}")

        drv_data = deriv_json[drv_path]

        # Get input derivations
        input_derivations = set()
        if "inputDrvs" in drv_data:
            input_derivations.update(drv_data["inputDrvs"].keys())

        # Get input sources
        input_sources = set()
        if "inputSrcs" in drv_data:
            input_sources.update(drv_data["inputSrcs"])

        # Get output paths
        output_paths = {}
        if "outputs" in drv_data:
            for output_name, output_data in drv_data["outputs"].items():
                if isinstance(output_data, dict) and "path" in output_data:
                    output_paths[output_name] = output_data["path"]

        return DerivationInfo(
            drv_path=drv_path,
            input_derivations=input_derivations,
            input_sources=input_sources,
            output_paths=output_paths
        )

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error getting derivation info: {e.stderr}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Error parsing derivation JSON: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error analyzing derivation: {str(e)}")

def build_dependency_tree(target_drv: str) -> Dict[str, DerivationInfo]:
    """
    Build a complete dependency tree for a derivation including all build-time dependencies
    """
    dependency_map: Dict[str, DerivationInfo] = {}
    to_process = {target_drv}
    processed = set()

    while to_process:
        current_drv = to_process.pop()
        if current_drv in processed:
            continue

        try:
            info = get_derivation_info(current_drv)
            dependency_map[current_drv] = info

            # Add all input derivations to processing queue
            to_process.update(info.input_derivations - processed)

            processed.add(current_drv)

        except Exception as e:
            print(f"Error processing derivation {current_drv}: {str(e)}", file=sys.stderr)
            raise

    return dependency_map

def print_tree_stats(dependency_map: Dict[str, DerivationInfo]) -> None:
    """Print summary statistics about the dependency tree"""
    total_derivations = len(dependency_map)
    total_source_files = sum(len(info.input_sources) for info in dependency_map.values())
    total_outputs = sum(len(info.output_paths) for info in dependency_map.values())

    print("\nDependency Tree Statistics:")
    print(f"Total derivations: {total_derivations}")
    print(f"Total source files: {total_source_files}")
    print(f"Total output paths: {total_outputs}")

    # Print details of the first few derivations as a sample
    print("\nSample of derivations (first 10):")
    for i, (drv_path, info) in enumerate(list(dependency_map.items())[:10]):
        print(f"\nDerivation {i+1}:")
        print(f"  Path: {drv_path}")
        print(f"  Input derivations: {len(info.input_derivations)}")
        if info.input_derivations:
            print(f"    First few inputs: {list(info.input_derivations)[:20]}")
        print(f"  Source files: {len(info.input_sources)}")
        if info.input_sources:
            print(f"    First few sources: {list(info.input_sources)[:20]}")
        print(f"  Outputs: {info.output_paths}")

def verify_signatures(drv_path: str) -> None:
    """Verify signatures for a derivation"""
    print(f"Starting verification for derivation: {drv_path}")

    try:
        # Build the dependency tree
        print("\nBuilding dependency tree...")
        dependency_map = build_dependency_tree(drv_path)

        # Print statistics about what we found
        print_tree_stats(dependency_map)

        # TODO: Next steps will be:
        # 1. Collect signatures for each derivation
        # 2. Verify signatures against trusted keys
        # 3. Build the verified dependency tree

    except Exception as e:
        print(f"Error during verification: {str(e)}", file=sys.stderr)
        raise