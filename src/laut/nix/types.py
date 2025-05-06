from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple
from types import MappingProxyType
from lautr import hash_upstream_placeholder

UnresolvedInputHash = str
ResolvedInputHash = str
DrvPath = str
ContentHash = str

# all this input resolution stuff is pretty half-baked
# maybe this should be the big typed thing that return from
# recursing through the build-time closure
# so it would have a couple of things
#class InputResolution:
# some way to understand what a specific unresolved derivation resolves to
# but we also may need to tie this intermediary result to a specific 'part'
# of the trust model somehow
# grouping resolved derivations in key-specific subsets could work
# for not counting keys twice, which produced two different resolutions
#    {{resolved_drv1, reolved_drv2}, {resolved_drv3}}
# while if we want to support constructing trust models via nesting,
# which might make sense and would be very elegant, because we can build a lot
# up that way starting from the threshold function that is kind of outlined
# in the comments that are part of the VM tests
# we could address those subgroups using hashes of the set of keys they contain, merkle-style
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
    json_attrs: MappingProxyType = field(repr=False)
    input_hash: UnresolvedInputHash
    inputs: Set['UnresolvedReferencedInputs'] = field(repr=False)
    outputs: MappingProxyType[str, 'UnresolvedOutput'] = field(repr=False)
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
    inputs: MappingProxyType[str, 'UnresolvedOutput']

    def __hash__(self):
        hashable_inputs = frozenset(self.inputs.items())
        return hash((self.derivation, hashable_inputs))

    def __eq__(self, other):
        if not isinstance(other, UnresolvedReferencedInputs):
            return False
        return (self.derivation == other.derivation) and (
            frozenset(self.inputs.items()) == frozenset(other.inputs.items()))

@dataclass(frozen=True)
class TrustlesslyResolvedDerivation:
    """Base information about a derivation"""
    resolves: UnresolvedDerivation = field(repr=False)
    drv_path: Optional[str] # FODs don't have this they should probably be a differnt class to make this cleaner
    input_hash: ResolvedInputHash
    #inputs: Dict[UnresolvedDerivation, 'ResolvedDerivation']
    outputs: MappingProxyType['UnresolvedOutput', ContentHash]

    def placeholder_for(self, output: str):
        return hash_upstream_placeholder(self.drv_path, output)

    def __hash__(self):
        hashable_outputs = frozenset(self.outputs.items())
        return hash((self.input_hash, hashable_outputs))

    def __eq__(self, other):
        if not isinstance(other, TrustlesslyResolvedDerivation):
            return False
        return self.input_hash == other.input_hash and frozenset(self.outputs.items()) == frozenset(other.outputs.items())

@dataclass(frozen=True)
class UnresolvedOutput:
    """Represents a resolved input with its specific output"""
    """For trustfully resolved derivations we should verify signatures on the output level"""
    """For trustlessly resolved derivations we verify on the derivation level and go by that"""
    output_name: str
    drv_path: str
    input_hash: Optional[UnresolvedInputHash]
    unresolved_path: str # this only exists for input addressed derivations

    def placeholder(self):
        return hash_upstream_placeholder(self.drv_path, self.output_name)

    def __hash__(self):
        return hash((self.input_hash, self.unresolved_path, self.output_name))

    def __eq__(self, other):
        if not isinstance(other, UnresolvedOutput):
            return False
        # the input hash already depends on the output name
        return (self.output_name == other.output_name and
            self.unresolved_path == self.unresolved_path and
            self.input_hash == other.input_hash)

ResolvedDerivation = TrustlesslyResolvedDerivation
