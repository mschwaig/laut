from dataclasses import dataclass, field
from typing import Dict, Set, Optional, List
import subprocess
import json
import itertools
import jwt
from .nix.commands import (
    get_derivation,
    check_nixos_cache,
    get_from_nixos_cache,
)
from .nix.constructive_trace import (
    compute_CT_input_hash,
)
from .nix.deep_constructive_trace import (
    get_DCT_input_hash,
)
from .nix.types import (
    UnresolvedDerivation
)
from .storage import get_s3_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)
from loguru import logger

DerivationInfo = str
ResolvedDerivationInfo = str
ResolvedInput = str

@dataclass(frozen=True)
class DerivationInput:
    """Represents an input dependency with its specific output"""
    derivation: 'DerivationInfo'
    output_name: str

    def __hash__(self):
        return hash((self.derivation.drv_path, self.output_name))

    def __eq__(self, other):
        if not isinstance(other, DerivationInput):
            return False
        return (self.derivation.drv_path == other.derivation.drv_path and
                self.output_name == other.output_name)

def get_derivation_type(drv_path: str) -> tuple[bool, bool]:
    """Determine if a derivation is fixed-output and/or content-addressed"""
    try:
        drv_data = get_derivation(drv_path)

        # Check for fixed-output
        env = drv_data.get("env", {})
        is_fixed_output = bool(env.get("outputHash", ""))

        # Check for content-addressing
        is_content_addressed = bool(drv_data.get("__contentAddressed", False))

        return is_fixed_output, is_content_addressed
    except Exception:
        logger.exception("error determining derivation type")
        raise

def get_output_names(drv_path: str) -> Set[str]:
    """Get all output names for a derivation"""
    try:
        drv_data = get_derivation(drv_path)
        return set(drv_data.get("outputs", {}).keys())
    except Exception as e:
        logger.exception("Error getting output names")
        raise

def get_fixed_output_hashes(drv_info: DerivationInfo) -> Dict[str, str]:
    """Get predefined output hashes for a fixed-output derivation"""
    try:
        drv_data = get_derivation(drv_info.drv_path)

        output_hashes = {}
        env = drv_data.get("env", {})

        # Handle both single and multiple outputs
        output_hash = env.get("outputHash")
        if output_hash:
            for output_name in get_output_names(drv_info.drv_path):
                output_hashes[output_name] = output_hash
        else:
            # Handle per-output hashes if present
            for output_name in get_output_names(drv_info.drv_path):
                hash_var = f"outputHash{output_name.capitalize()}"
                if hash_var in env:
                    output_hashes[output_name] = env[hash_var]

        if not output_hashes:
            raise ValueError("No output hashes found for fixed-output derivation")

        return output_hashes
    except Exception:
        logger.exception("Error getting fixed output hashes")
        raise

class SignatureVerifier:
    """Main verification class for build traces"""

    def __init__(self, caches: List[str], trusted_keys: Dict[str, Ed25519PublicKey]):
        self.caches = caches
        self.trusted_keys = trusted_keys

    def get_signatures(self, input_hash: str) -> List[dict]:
        """Fetch and parse signatures from all configured caches"""
        all_signatures = []
        for cache_url in self.caches:
            try:
                s3_info = get_s3_client(cache_url, anon=True)
                s3_client = s3_info['client']
                bucket = s3_info['bucket']
                key = f"traces/{input_hash}"

                try:
                    response = s3_client.get_object(Bucket=bucket, Key=key)
                    content = response['Body'].read()
                    if content:
                        parsed_content = json.loads(content)
                        all_signatures.extend(parsed_content.get("signatures", []))
                except s3_client.exceptions.NoSuchKey:
                    logger.exception(f"no signatures found at {key}")
                    continue
            except Exception:
                logger.exception(f"error fetching signatures from {cache_url}")
                continue
        logger.debug("Signatures found for input hash {input_hash}: {all_signatures}")

        return all_signatures

    def verify_signature_payload(self, signature: str) -> Optional[dict]:
        """Verify a JWS signature against trusted keys"""
        try:
            # Extract header without verification to get key ID
            header = jwt.get_unverified_header(signature)
            if 'kid' not in header:
                logger.warn("no key ID in signature header")
                return None

            key_name = header['kid']
            if key_name not in self.trusted_keys:
                logger.warn(f"key {key_name} not in trusted keys")
                return None

            try:
                # Verify with EdDSA algorithm
                payload = jwt.decode(
                    signature,
                    key=self.trusted_keys[key_name],
                    algorithms=["EdDSA"]
                )
                logger.debug(f"Signature {signature} is valid.")
                return payload
            except jwt.InvalidSignatureError:
                logger.exception(f"invalid signature for key {key_name}")
                return None
            except Exception:
                logger.exception(f"Error verifying with key {key_name}")
                return None

        except Exception:
            logger.exception(f"error verifying signature")
            return None

    def verify_trace_signatures(self, signatures: List[str], input_hash: str) -> List[Dict[str, str]]:
        """
        Verify signatures and collect valid output hashes

        Args:
            signatures: List of JWS signature tokens to verify
            input_hash: Expected input hash to validate against

        Returns:
            List[Dict[str, str]]: List of valid output hash mappings
        """
        valid_output_hashes = []

        for sig in signatures:
            payload = self.verify_signature_payload(sig)
            if payload and payload.get("in") == input_hash:
                output_hashes = payload.get("out")
                if isinstance(output_hashes, dict):
                    valid_output_hashes.append(output_hashes)

        logger.debug(f"Found {len(valid_output_hashes)} valid output hash mappings")
        return valid_output_hashes

    def build_derivation_tree(self, target_drv: str) -> DerivationInfo:
        """Build the complete dependency tree"""
        processed_drvs: Dict[str, DerivationInfo] = {}

        def process_derivation(drv_path: str) -> DerivationInfo:
            if drv_path in processed_drvs:
                return processed_drvs[drv_path]

            is_fixed_output, is_content_addressed = get_derivation_type(drv_path)
            unresolved_input_hash = get_DCT_input_hash(drv_path)

            drv_info = DerivationInfo(
                drv_path=drv_path,
                unresolved_input_hash=unresolved_input_hash,
                is_fixed_output=is_fixed_output,
                is_content_addressed=is_content_addressed
            )
            processed_drvs[drv_path] = drv_info

            # Process inputs recursively
            for input_drv, output in self.get_derivation_inputs(drv_path):
                input_info = process_derivation(input_drv)
                drv_info.inputs.add(DerivationInput(
                    derivation=input_info,
                    output_name=output
                ))

            return drv_info

        return process_derivation(target_drv)

    def get_derivation_inputs(self, drv_path: str) -> List[tuple[str, str]]:
        """Get all inputs and their output names for a derivation"""
        try:
            drv_data = get_derivation(drv_path)

            inputs = []
            if "inputDrvs" in drv_data:
                for input_drv, input_data in drv_data["inputDrvs"].items():
                    for output in input_data:
                        inputs.append((input_drv, output))

            return inputs
        except Exception:
            logger.exception("error getting derivation inputs")
            raise

    def resolve_fixed_output(self, drv_info: DerivationInfo) -> bool:
        """Resolve a fixed-output derivation"""
        try:
            output_hashes = get_fixed_output_hashes(drv_info)
            resolution = ResolvedDerivationInfo(
                resolved_input_hash=drv_info.unresolved_input_hash,
                output_hashes=output_hashes
            )
            drv_info.resolutions.add(resolution)
            return True
        except Exception:
            logger.exception("error resolving fixed-output derivation")
            return False

    def get_input_resolution_combinations(self, drv_info: DerivationInfo) -> List[Set[ResolvedInput]]:
        """Get all possible combinations of input resolutions"""
        input_resolution_options = []
        for input_drv in drv_info.inputs:
            input_resolutions = set()
            for resolution in input_drv.derivation.resolutions:
                input_resolutions.add(ResolvedInput(
                    resolution=resolution,
                    output_name=input_drv.output_name
                ))
            input_resolution_options.append(input_resolutions)

        return [set(combo) for combo in itertools.product(*input_resolution_options)]

    def get_output_info_from_cache(self, drv_path: str) -> Dict[str, Dict[str, str]]:
            """
            Get output path and hash information from the nixos cache.
            Returns a dictionary mapping output names to their hashes.
            """
            try:
                outputs_info = get_from_nixos_cache(drv_path)

                output_hashes = {}

                # Process each output path
                for path, info in outputs_info.items():
                    logger.debug(f"Processing output path: {path}")
                    if info is None:
                        logger.debug(f"Skipping {path}: info is None")
                        continue

                    # Check for valid nixos cache signature
                    signatures = info.get("signatures", [])
                    logger.debug(f"Found signatures: {signatures}")
                    has_valid_sig = any(sig.startswith("cache.nixos.org-1:") for sig in signatures)
                    if not has_valid_sig:
                        logger.debug(f"Skipping {path}: no valid nixos cache signature")
                        continue

                    # Get narHash
                    nar_hash = info.get("narHash")
                    if not nar_hash:
                        logger.debug(f"Skipping {path}: no narHash")
                        continue

                    # TODO: This assumes the output name can be derived from the path suffix
                    # We might need a more robust way to map outputs to their names
                    if path.endswith("-man"):
                        output_name = "man"
                    elif path.endswith("-dev"):
                        output_name = "dev"
                    elif path.endswith("-doc"):
                        output_name = "doc"
                    else:
                        output_name = "out"  # Assume default output is called "out"

                    logger.debug(f"Adding output {output_name} with hash {nar_hash}")
                    output_hashes[output_name] = nar_hash

                if not output_hashes:
                    logger.error(f"no valid signed output for {drv_path}")
                    raise ValueError(f"No valid signed outputs found for {drv_path}")

                logger.debug(f"Final output hashes: {output_hashes}")
                return output_hashes

            except subprocess.CalledProcessError:
                logger.exception("error running nix path-info")
                raise
            except json.JSONDecodeError:
                logger.exception("error parsing JSON output")
                raise
            except Exception:
                logger.exception("unexpected error getting output info")
                raise

    def resolve_derivation(self, drv_info: DerivationInfo) -> bool:
        """Attempt to resolve a derivation"""
        logger.debug(f"\nAttempting to resolve: {drv_info.drv_path}")
        logger.debug(f"Is content-addressed: {drv_info.is_content_addressed}")

        if drv_info.is_resolved():
            logger.debug("Already resolved, returning True")
            return True

        if drv_info.is_fixed_output:
            logger.debug("Fixed output derivation, using resolve_fixed_output")
            return self.resolve_fixed_output(drv_info)

        success = False
        input_resolution_combinations = list(self.get_input_resolution_combinations(drv_info))
        logger.debug(f"Found {len(input_resolution_combinations)} input resolution combinations")

        for input_resolutions in input_resolution_combinations:
            logger.debug(f"\nTrying input resolution combination:")
            for res in input_resolutions:
                logger.debug(f"  - {res.resolution.resolved_input_hash} ({res.output_name})")

            resolved_input_hash = drv_info.compute_resolved_input_hash(input_resolutions)
            logger.debug(f"Computed resolved input hash: {resolved_input_hash}")

            signatures = self.get_signatures(resolved_input_hash)
            logger.debug(f"Found {len(signatures)} signatures")

            valid_output_hashes = self.verify_trace_signatures(signatures, resolved_input_hash)
            logger.debug(f"Valid output hashes: {valid_output_hashes}")

            for output_hashes in valid_output_hashes:
                logger.debug(f"Creating resolution with output hashes: {output_hashes}")
                resolution = ResolvedDerivationInfo(
                    resolved_input_hash=resolved_input_hash,
                    output_hashes=output_hashes,
                    input_resolutions=input_resolutions
                )
                logger.debug("Adding resolution to drv_info")
                drv_info.resolutions.add(resolution)
                success = True

        if success:
            logger.debug("Successfully resolved with content-addressed method")
            return success

        # If we get here, we failed to resolve with content-addressed method
        # For input-addressed derivations, check nixos cache as well
        # this bypasses our regular requirements for verification
        # and it does not properly verify the legacy signature format yet,
        # so we will need to do this differently in the future and for stricter
        # turst models which do not trust those particular le
        logger.debug("\nTrying nixos cache fallback")
        if not drv_info.is_content_addressed:
            logger.debug("Derivation is input-addressed, checking nixos cache as well")
            if check_nixos_cache(drv_info.drv_path):
                try:
                    output_hashes = self.get_output_info_from_cache(drv_info.drv_path)
                    logger.debug(f"Got output hashes from cache: {output_hashes}")

                    resolution = ResolvedDerivationInfo(
                        resolved_input_hash=None,
                        has_unknown_inputs=True,
                        output_hashes=output_hashes,
                        input_resolutions=set()
                    )
                    logger.debug("Adding cache-based resolution to drv_info")
                    drv_info.resolutions.add(resolution)
                    return True
                except Exception:
                    logger.exception("error creating resolution for cache hit")
                    return False
        else:
            logger.debug("derivation is content-addressed, skipping nixos cache")

        logger.debug("failed to resolve derivation")
        return False

    def verify_derivation_tree(self, target_drv: str) -> bool:
        """Main verification entry point"""
        root = self.build_derivation_tree(target_drv)
        unresolved = {drv_info.drv_path: drv_info
                     for drv_info in self._collect_all_derivations(root)}

        while unresolved:
            for drv_path, drv_info in unresolved.items():
                logger.debug(f"Drv {drv_path}:")
                logger.debug(f"  is_resolved: {drv_info.is_resolved()}")
                logger.debug(f"  can_resolve: {drv_info.can_resolve()}")
                logger.debug(f"  input states: {[(i.derivation.drv_path, i.derivation.is_resolved()) for i in drv_info.inputs]}")
                logger.debug(f"  resolutions: {drv_info.resolutions}")
            progress = False
            resolvable = [drv_info for drv_info in unresolved.values()
                         if drv_info.can_resolve()]

            for drv_info in resolvable:
                if self.resolve_derivation(drv_info):
                    logger.debug(f"Resolved {drv_info.drv_path} with outputs: {
                        [resolution.output_hashes for resolution in drv_info.resolutions]
                    }")
                    del unresolved[drv_info.drv_path]
                    progress = True

            if not progress and unresolved:
                logger.debug(f"Failed to resolve: {', '.join(drv_path for drv_path in unresolved.keys())}")
                for drv_path, drv_info in unresolved.items():
                    logger.debug(f"Drv {drv_path}:")
                    logger.debug(f"  is_resolved: {drv_info.is_resolved()}")
                    logger.debug(f"  can_resolve: {drv_info.can_resolve()}")
                    logger.debug(f"  input states: {[(i.derivation.drv_path, i.derivation.is_resolved()) for i in drv_info.inputs]}")
                    logger.debug(f"  resolutions: {drv_info.resolutions}")
                return False

        return root.is_resolved()

    def _collect_all_derivations(self, root: DerivationInfo) -> Set[DerivationInfo]:
        """Helper to collect all derivations in the tree"""
        result = {root}
        for input_drv in root.inputs:
            result.update(self._collect_all_derivations(input_drv.derivation))
        return result

def verify_signatures(drv_path: str, caches: List[str], trusted_keys: Dict[str, Ed25519PublicKey]) -> bool:
    """Main verification entry point for external use"""
    verifier = SignatureVerifier(caches, trusted_keys)
    return verifier.verify_derivation_tree(drv_path)


### --- new hand-written, unit-tested stuff after this line ---


def get_initial_required_outputs(node_drv_path: str, json: dict) -> List[str]:
    outputs = map(lambda x: (x.key, x.value), json[node_drv_path]["outputs"])

    # TODO: transform this
    return outputs

def build_unresolved_tree(node_drv_path: str, json: dict) -> UnresolvedDerivation:
    get_initial_required_outputs = get_initial_required_outputs(node_drv_path, json)
    return build_unresolved_tree_rec(node_drv_path, json, get_initial_required_outputs)

def build_unresolved_tree_rec(node_drv_path: str, json: dict, outputs: List[str]) -> UnresolvedDerivation:
    inputs = json[node_drv_path]["inputDrvs"]

    input_drvs = map(lambda x: (x, build_unresolved_tree_rec(x, json)), inputs.keys)
    # TODO construct relevant outputs
    input_outputs = input_drvs
    is_fixed_output, is_content_addressed = get_derivation_type(node_drv_path)
    return UnresolvedDerivation(
        input_hash=get_DCT_input_hash(node_drv_path),
        inputs=input_outputs,
        outputs=outputs,
        is_content_addressed=is_content_addressed,
        is_fixed_output=is_fixed_output,
    )