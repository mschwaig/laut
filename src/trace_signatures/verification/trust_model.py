from dataclasses import dataclass
from typing import Set

from ..nix.types import (
    ResolvedDerivation,
    ResolvedInputHash,
    UnresolvedInputHash,
    TrustfullyResolvedDerivation,
    TrustlesslyResolvedDerivation
)

KeyFingerprint = str

@dataclass(frozen=True)
class TrustedKey:
    fingerprint: KeyFingerprint
    name: str
    isLegacy: bool

    #def contains_legacy_keys(self):
    #    return self.isLegacy

    def ct_verify(self, ct_input_hash: ResolvedInputHash, ct_signatures) -> Set[ResolvedDerivation]:
        # TODO: verify
        return set()

    def dct_verify(self, dct_input_hash: UnresolvedInputHash, dct_signatures) -> Set[ResolvedDerivation]:
        # TODO: verify
        return set()

    def __hash__(self):
        return hash((self.fingerprint, self.isLegacy, self.name))

    def __eq__(self, other):
        if not isinstance(other, TrustedKey):
            return False
        return (self.fingerprint == other.fingerprint) and (
            self.isLegacy == other.isLegacy) and (
            self.name == other.name
        )

@dataclass(frozen=True)
class KeySetWithTreshold:
    components: Set['TrustModel']
    treshold: int # only outermost layer of threshold can have legacy keys maybe?

    def __post_init__(self):
        if self.treshold < 1 or self.treshold > len(self.components):
            raise ValueError("invalid trust model")

    #def contains_legacy_keys(self):
    #    return any(map(lambda x: x.contains_legacy_keys(), self.components))

    def ct_verify(self, ct_input_hash: ResolvedInputHash, ct_signatures) -> Set[ResolvedDerivation]:
        # group by signed output
        # do the sum thing for each output
        # actually scratch those two lines, we probably need to just gather all
        # of the signatures first and check if we have enough co-inciding transitive runtime closures
        # return a set with those which surpass the treshold
        #return sum(1 for x in self.components if x.ct_verify(ct_input_hash, ct_signatures)) >= self.treshold
        return set()

    def dct_verify(self, dct_input_hash: UnresolvedInputHash, dct_signatures) -> Set[ResolvedDerivation]:
        # do the threshold thing for each combination of inputs
        #return sum(1 for x in self.components if x.dct_verify(dct_input_hash, dct_signatures)) >= self.treshold
        return set()

    def __hash__(self):
        return hash((self.components, self.treshold))

    def __eq__(self, other):
        if not isinstance(other, KeySetWithTreshold):
            return False
        return (self.components == other.components) and (
            self.treshold == other.treshold)

TrustModel = TrustedKey | KeySetWithTreshold
