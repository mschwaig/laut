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

TrustModel = TrustedKey