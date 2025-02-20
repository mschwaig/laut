from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

UnresolvedInputHash = str
ResolvedInputHash = str
DrvPath = str
ContentHash = str

# all this input resolution stuff is pretty half-baked
# maybe this should be the big typed thing that return from
# recursing through the build-time closure
# so it woudl have a couple of things
#class InputResolution:
# some way to understand what a specific unresovled derivation resolves to
# but we also may need to tie this intermediary result to a specific 'part'
# of the trust model somehow
# grouping resolved derivations in key-specific subsets could work
# for not counting keys twice, which produced two different resolutions
#    {{resolved_drv1, reolved_drv2}, {resolved_drv3}}
# while if we want to support constructing trust models via nesting,
# which might make sense and would be very elegant, because we can build a lot
# up that way starting from the threshold function that is kind of outlined
# in the comments that are part of the VM tests
# we could address those subgroups using hashes of the set of keys they countain, merkle-style
# sadly that does not necessarily give good answers about what should come out of the lookup
# for subgroups ... the set of keys? or the set of resolved derivations?
# set of keys seems to make sense, but not sure
# this needs more thought
#    (subgroup_key) -> list [subgroup_key | resolved_drv]

PossibleInputResolutions = Set[Set[Tuple['ResolvedDerivation', str]]]

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
    outputs: Dict['UnresolvedOutput', ContentHash]

    def __hash__(self):
        return hash(self.input_hash)

    def __eq__(self, other):
        if not isinstance(other, TrustlesslyResolvedDerivation):
            return False
        return self.input_hash == other.input_hash

@dataclass(frozen=True)
class UnresolvedOutput:
    """Represents a resolved input with its specific output"""
    """For trustfully resolved derivations we should verify signatures on the output level"""
    """For trustlessly resolved derivations we verify on the derivation level and go by that"""
    output_name: str
    input_hash: Optional[UnresolvedInputHash] # this only exists for input addressed derivations

    def __hash__(self):
        return hash((self.input_hash, self.input_hash))

    def __eq__(self, other):
        if not isinstance(other, UnresolvedOutput):
            return False
        # the input hash already depends on the output name
        return (self.output_name == other.output_name and
            self.input_hash == other.input_hash)

ResolvedDerivation = TrustlesslyResolvedDerivation
