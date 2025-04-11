from dataclasses import dataclass
from typing import Set

from ..verification.verify_signatures import verify_resolved_trace_signature

from ..nix.types import (
    UnresolvedDerivation,
    ResolvedInputHash,
    UnresolvedInputHash,
    TrustlesslyResolvedDerivation,
    ContentHash
)

@dataclass (frozen=True)
class TrustedKey:
    key_bytes: bytes
    name: str
    #isLegacy: bool

    #def contains_legacy_keys(self):
    #    return self.isLegacy

    def ct_verify(self, unresolved_drv: UnresolvedDerivation, ct_input_hash: ResolvedInputHash, resolution, ct_signatures) -> Set[Set[TrustlesslyResolvedDerivation]]:
        # ensure that signature is correctly signed with trusted key
        # and has the correct ct_input_hash
        # and then return the set of resolved derivations for which this holds
        # what we return here is basically {{drv1,drv2,drv3}} because they all belong to the same key
        # if the keys were different we would return {{drv1}, {drv2}, {drv3}}
        output_mappings = verify_resolved_trace_signature(self.key_bytes, ct_signatures, ct_input_hash)
        # not sure if I can get rid of str(v) since v should already be a str
        typed_mappings = list(map(lambda mapping: {unresolved_drv.outputs[k]: ContentHash(v) for k, v in mapping.items()}, output_mappings))
        #typed_sets = set(map(lambda mapping: (map(lambda output: ResolvedOutput(resolved_drv, resolved_drv.resolves.outputs[output], mapping[output]), mapping)), output_mappings))
        typed_sets = set(set(map(lambda mapping: TrustlesslyResolvedDerivation(
            resolves=unresolved_drv,
            input_hash=ct_input_hash,
            inputs=resolution,
            outputs=mapping
        ), typed_mappings)))

        # TODO: get this to work

        return set()

    #def dct_verify(self, dct_input_hash: UnresolvedInputHash, dct_signatures) -> Set[ResolvedDerivation]:
        # TODO: verify
    #    return set()

    def __hash__(self):
        return hash((self.key_bytes, self.name)) # isLegacy

    def __eq__(self, other):
        if not isinstance(other, TrustedKey):
            return False
        return (self.key_bytes == other.key_bytes) and (
            # self.str == other.isLegacy) and (
            self.name == other.name
        )

@dataclass(frozen=True)
class KeySetWithThreshold:
    components: Set['TrustModel']
    threshold: int # only outermost layer of threshold can have legacy keys maybe?

    def __post_init__(self):
        if self.threshold < 1 or self.threshold > len(self.components):
            raise ValueError("invalid trust model")

    #def contains_legacy_keys(self):
    #    return any(map(lambda x: x.contains_legacy_keys(), self.components))

    def ct_verify(self, ct_input_hash: ResolvedInputHash, ct_signatures) -> Set[Set[TrustlesslyResolvedDerivation]]:
        # group by signed output
        # do the sum thing for each output
        # actually scratch those two lines, we probably need to just gather all
        # of the signatures first and check if we have enough co-inciding transitive runtime closures
        # return a set with those which surpass the threshold
        #return sum(1 for x in self.components if x.ct_verify(ct_input_hash, ct_signatures)) >= self.threshold
        return set()

    def dct_verify(self, dct_input_hash: UnresolvedInputHash, dct_signatures) ->Set[Set[TrustlesslyResolvedDerivation]]:
        # do the threshold thing for each combination of inputs
        #return sum(1 for x in self.components if x.dct_verify(dct_input_hash, dct_signatures)) >= self.threshold
        return set()

    def __hash__(self):
        return hash((self.components, self.threshold))

    def __eq__(self, other):
        if not isinstance(other, KeySetWithThreshold):
            return False
        return (self.components == other.components) and (
            self.threshold == other.threshold)

TrustModel = TrustedKey | KeySetWithThreshold
