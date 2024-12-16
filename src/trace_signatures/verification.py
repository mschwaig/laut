from dataclasses import dataclass
from typing import Set, Dict, List, Optional
import sys
import json
import subprocess
from pathlib import Path
from .utils import debug_print, compute_sha256_base64, get_canonical_derivation
from .storage import get_s3_client

@dataclass
class DerivationInfo:
    """Information about a derivation and its dependencies"""
    drv_path: str
    input_derivations: Set[str]  # Paths to input derivations
    input_sources: Set[str]      # Paths to source files
    output_paths: Dict[str, str] # Output name -> output path mapping

@dataclass
class BuildStep:
    """Represents a build step with its dependency resolution state"""
    drv_path: str
    input_hash: str  # Canonical input hash for signature lookup
    output_hash: Optional[str] = None  # Will be populated when resolved
    unresolved_count: int = 0  # Count of unresolved dependencies
    dependent_steps: Set[str] = None  # Steps that depend on this one
    resolved_inputs: Dict[str, str] = None  # Map of input drv paths to their resolved output hashes

    def __post_init__(self):
        if self.dependent_steps is None:
            self.dependent_steps = set()
        if self.resolved_inputs is None:
            self.resolved_inputs = {}

def get_derivation_info(drv_path: str) -> DerivationInfo:
    """Get detailed information about a derivation including all its dependencies"""
    try:
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

        input_derivations = set()
        if "inputDrvs" in drv_data:
            input_derivations.update(drv_data["inputDrvs"].keys())

        input_sources = set()
        if "inputSrcs" in drv_data:
            input_sources.update(drv_data["inputSrcs"])

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
    """Build a complete dependency tree for a derivation"""
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
            to_process.update(info.input_derivations - processed)
            processed.add(current_drv)

        except Exception as e:
            debug_print(f"Error processing derivation {current_drv}: {str(e)}")
            raise

    return dependency_map

class SignatureVerifier:
    def __init__(self, caches: List[str], trusted_keys: Set[str]):
        self.caches = caches
        self.trusted_keys = trusted_keys
        self.build_steps: Dict[str, BuildStep] = {}
        self.resolved_steps: Set[str] = set()

    def initialize_from_dependency_map(self, dependency_map: Dict[str, DerivationInfo]):
        """Convert dependency map into build steps with resolution tracking"""
        # First pass: Create all build steps
        for drv_path, info in dependency_map.items():
            canonical = get_canonical_derivation(drv_path)
            input_hash = compute_sha256_base64(canonical)

            self.build_steps[drv_path] = BuildStep(
                drv_path=drv_path,
                input_hash=input_hash,
                unresolved_count=len(info.input_derivations)
            )

        # Second pass: Set up dependency relationships
        for drv_path, info in dependency_map.items():
            current_step = self.build_steps[drv_path]
            for input_drv in info.input_derivations:
                self.build_steps[input_drv].dependent_steps.add(drv_path)

    def get_signatures(self, input_hash: str) -> List[dict]:
        """Fetch signatures for a given input hash from all configured caches"""
        all_signatures = []
        for cache_url in self.caches:
            try:
                s3_info = get_s3_client(cache_url, anon=True)
                s3_client = s3_info['client']
                bucket = s3_info['bucket']
                key = f"traces/{input_hash}"

                debug_print(f"Attempting to fetch from bucket: {bucket}, key: {key}")

                try:
                    response = s3_client.get_object(Bucket=bucket, Key=key)
                    debug_print(f"S3 response status: {response['ResponseMetadata']['HTTPStatusCode']}")

                    content = response['Body'].read()
                    debug_print(f"Received content length: {len(content)}")
                    debug_print(f"Raw content: {content[:200]}...")  # Print first 200 chars

                    if content:
                        parsed_content = json.loads(content)
                        all_signatures.extend(parsed_content.get("signatures", []))

                except s3_client.exceptions.NoSuchKey:
                    debug_print(f"No object found at {key}")
                    continue

            except Exception as e:
                debug_print(f"Error fetching signatures from {cache_url}: {str(e)}")
                continue

        return all_signatures

    def filter_valid_signatures(self, signatures: List[dict]) -> List[dict]:
        """Filter signatures based on trusted keys and other criteria"""
        # TODO: Implement actual signature validation
        return signatures

    def resolve_step(self, step: BuildStep) -> bool:
        """Attempt to resolve a build step by finding and validating signatures"""
        signatures = self.get_signatures(step.input_hash)

        if not signatures:
            debug_print(f"No signatures found for {step.drv_path}")
            return False

        valid_signatures = self.filter_valid_signatures(signatures)
        if not valid_signatures:
            debug_print(f"No valid signatures found for {step.drv_path}")
            return False

        # For now, just take the first valid signature
        signature = valid_signatures[0]
        step.output_hash = signature["out"]

        # Mark as resolved
        self.resolved_steps.add(step.drv_path)

        # Update dependent steps
        for dep_path in step.dependent_steps:
            dep_step = self.build_steps[dep_path]
            dep_step.resolved_inputs[step.drv_path] = step.output_hash
            dep_step.unresolved_count -= 1

        return True

    def verify(self, target_drv: str) -> bool:
        """Verify the complete dependency chain"""
        while True:
            # Find steps with no unresolved dependencies
            ready_steps = [
                step for step in self.build_steps.values()
                if step.drv_path not in self.resolved_steps and step.unresolved_count == 0
            ]

            if not ready_steps:
                # Check if we're done
                if target_drv in self.resolved_steps:
                    return True
                debug_print("No more steps to resolve but target not verified")
                return False

            # Try to resolve each ready step
            progress = False
            for step in ready_steps:
                if self.resolve_step(step):
                    progress = True

            if not progress:
                debug_print("Unable to make progress resolving signatures")
                return False

def verify_signatures(drv_path: str, caches: List[str] = None, trusted_keys: Set[str] = None) -> bool:
    """Main verification entry point"""
    #if caches is None:
    # set caches here manually for easier debuging
    #caches = ["s3://binary-cache?endpoint=http://localhost:9000&region=eu-west-1"]
    if trusted_keys is None:
        trusted_keys = set()

    debug_print(f"Starting verification for {drv_path} using caches: {caches}")

    # Build the dependency tree
    dependency_map = build_dependency_tree(drv_path)

    # Create and initialize the verifier
    verifier = SignatureVerifier(caches, trusted_keys)
    verifier.initialize_from_dependency_map(dependency_map)

    # Run the verification
    return verifier.verify(drv_path)