from dataclasses import dataclass
from typing import Dict, Set, Tuple

UnresolvedInputHash = str
ResolvedInputHash = str
DrvPath = str
ContentHash = str

PossibleInputResolutions = Set[Tuple['ResolvedDerivation', str]]

InputResolutions = Dict['UnresolvedDerivation', 'ResolvedDerivation']

@dataclass(frozen=True)
class UnresolvedDerivation:
    """Base information about a derivation"""
    drv_path: DrvPath
    json_attrs: Dict
    input_hash: UnresolvedInputHash
    inputs: Set['UnresolvedReferencedInputs']
    outputs: Dict[str, 'UnresolvedOutput']
    is_fixed_output: bool = False
    is_content_addressed: bool = False

    def __hash__(self):
        return hash(self.input_hash)

    def __eq__(self, other):
        if not isinstance(other, UnresolvedDerivation):
            return False
        return self.input_hash == other.input_hash

@dataclass(frozen=True)
class UnresolvedReferencedInputs:
    derivation: UnresolvedDerivation
    inputs: Dict[str, 'UnresolvedOutput']

    def __hash__(self):
         # TODO: not sure if the .values() is ok here
        return hash((self.derivation, self.inputs.values()))

    def __eq__(self, other):
        if not isinstance(other, UnresolvedReferencedInputs):
            return False
        return (self.derivation == other.derivation) and (
            self.inputs == other.inputs)

@dataclass(frozen=True)
class TrustlesslyResolvedDerivation:
    """Base information about a derivation"""
    resolves: UnresolvedDerivation
    input_hash: ResolvedInputHash
    inputs: Dict[UnresolvedDerivation, 'ResolvedDerivation']

    def __hash__(self):
        return hash(self.input_hash)

    def __eq__(self, other):
        if not isinstance(other, TrustlesslyResolvedDerivation):
            return False
        return self.input_hash == other.input_hash

@dataclass(frozen=True)
class TrustfullyResolvedDerivation:
    """Base information about a derivation"""
    """TODO: the signature checks happen on the ResolvedOutput level for this"""
    """while for trustlessly resolved derivations we do it on this level"""
    resolves: UnresolvedDerivation

    def __hash__(self):
        return hash(self.resolves)

    def __eq__(self, other):
        if not isinstance(other, TrustfullyResolvedDerivation):
            return False
        return self.resolves == other.resolves

@dataclass(frozen=True)
class UnresolvedOutput:
    """Represents a resolved input with its specific output"""
    """For trustfully resolved derivations we should verify signatures on the output level"""
    """For trustlessly resolved derivations we verify on the derivation level and go by that"""
    output_name: str
    input_hash: UnresolvedInputHash

    def __hash__(self):
        return hash((self.input_hash, self.input_hash))

    def __eq__(self, other):
        if not isinstance(other, UnresolvedOutput):
            return False
        # the input hash already depends on the output name
        return (self.output_name == other.output_name and
            self.input_hash == other.input_hash)

@dataclass(frozen=True)
class ResolvedOutput:
    """Represents a resolved input with its specific output"""
    """For trustfully resolved derivations we should verify signatures on the output level"""
    """For trustlessly resolved derivations we verify on the derivation level and go by that"""
    resolution: 'ResolvedDerivation'
    resolves: 'UnresolvedOutput'
    output_hash: ContentHash

    def __hash__(self):
        return hash((self.resolution, self.resolves, self.output_hash))

    def __eq__(self, other):
        if not isinstance(other, ResolvedOutput):
            return False
        return (self.resolution == other.resolution and
                self.resolves == other.resolves and
                self.output_hash == other.output_hash
                )

ResolvedDerivation = TrustlesslyResolvedDerivation | TrustfullyResolvedDerivation

def compute_resolved_input_hash(drv: UnresolvedDerivation, input_resolutions: InputResolutions) -> TrustlesslyResolvedDerivation:
    """
    Compute the input hash for this derivation with specific input resolutions.
    """
    # transform input resolutions to content hashes
    # in same order as original derivation
    resolutions = list(map(lambda x: x.resolution.output_hashes[x.output_name], input_resolutions))
    resolved_input_hash = compute_CT_input_hash(drv.drv_path, resolutions)
    return TrustlesslyResolvedDerivation(drv, resolved_input_hash, input_resolutions)

#  I think we should not need this method anymore, because we should get this by construction
def _can_resolve(self) -> bool:
    return all(input_drv.derivation.is_resolved() for input_drv in self.inputs) or (
        any(resolution.has_unknown_inputs for resolution in self.resolutions)
    )