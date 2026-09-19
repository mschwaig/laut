# Format Design Principles

Openness and gradual verification have been design principles of laut from the
start. The format should enable Nix implementations to evolve, rather than hold
them back. Choices of envelope, payload schema, and implementation must support
these principles. The [provenance profile](slsa-provenance-v1.md) specifies the
current wire format; the [verification semantics](semantics.md) define reasoning
over admitted claims.

## Independent Evolution

Producers and consumers should be able to evolve independently. A producer can
record evidence that a consumer does not yet use, and different consumers can
support different evidence and verification methods. Supporting a new optional
representation must not require every implementation to upgrade together.
Producers can implement and describe new evidence without first coordinating
with laut or other implementations. Parties using that evidence must agree on
its meaning, but the format does not need to anticipate all such agreements.

Openness does not mean silently accepting unknown build semantics. Supplementary
evidence can be ignored only when doing so leaves the understood claim intact.
A departure that would be unsafe to ignore must instead make its requirements
explicit, so a consumer can decline that claim without excluding other claims
it understands.

## Evidence and Trust

Signed evidence can gradually replace reliance on a signer's word or human
procedures with verification of particular properties. This is incremental:
different consumers may verify different properties, and remaining assumptions
still need explicit trust boundaries. Evidence may be a producer's assertion,
the result of an enforcement or verification mechanism, or a verifiable
attestation whose semantics define guarantees about those checks. At the edges
of what is verifiable, trust in the signer or a human procedure can remain.

A signature authenticates who asserted metadata; it does not establish that the
assertion is true. Likewise, accepting a feature marker does not verify the
evidence associated with that feature.

Producers must truthfully describe their builds, including departures from
baseline assumptions. A marker mechanism cannot detect a signer concealing a
departure. Nor does an authenticated version string prove execution of that
software.

## Coexisting Representations

Multiple representations of inputs and outputs may coexist in a claim. They can
serve different consumers without forcing a universal choice of serialization,
content-addressing scheme, or evidence format. They are genuine siblings in a
ResourceDescriptor's nonempty `digest` map, with no universally required scheme.
`externalParameters.resolvedInput` describes the complete resolved request;
each named subject describes one logical output resource. All entries in a map
identify that same resource, not separate dependencies or separate outputs.
`resolvedDependencies` instead describes supplementary actual input resources,
not alternative representations of the complete request.

Coexistence provides compatibility and migration paths: a producer can publish a
new representation alongside one existing consumers understand. Consumers need
an identity they can actually use, not support for every representation present.
A descriptor containing only unknown schemes is structurally valid, even if the
current verifier cannot use it. Scheme keys are compared exactly, with no forced
namespace or version syntax. Each scheme defines what it identifies and its
encoding: a hash must define its preimage, while an immutable structured
reference need not be a hash at all. In particular, a castore Entry and a NAR
digest are distinct identifiers, not interchangeable byte encodings.

After accepting the signer under its trust policy, a verifier can trust the
signed assertion that these sibling identities describe the same resource. It
does not need an independent equivalence proof or a mathematical isomorphism
between schemes. One scheme may distinguish more detail than another while both
provide adequate identifiers for the resource. Signature verification alone does
not establish truth; trusting the relationship is an explicit trust decision.
Independent evidence, including hardware attestation, supplies only the
guarantees defined by that evidence, not an implicit guarantee of every scheme
relationship in the statement.

Multiple representations never create additional signer votes. Output maps
remain atomic: consumers must not union or synthesize representations or outputs
from separate claims to reach a threshold. The current Nix verifier requires a
usable Nix request identity and a Nix CA store path for every subject, otherwise
it skips the whole claim, not just unusable outputs or other cache entries.
These are implementation admission requirements, not universal format rules.

## Critical Departures

Criticality is needed when a feature violates monotonicity: ignoring its effect
could turn rejection into acceptance. For example, intentionally granting GPU
access may relax isolation assumptions that a consumer otherwise relies on.
Keep the signed marker set minimal: it declares only departures that are unsafe
to ignore, not every optional annotation, implementation detail, or extra digest.
An unknown or unaccepted marker makes the affected atomic build claim ineligible
for reasoning, not other claims in the same cache collection.

Markers are opaque, exact strings. There is no central registry, namespace,
prefix convention, or version syntax. Different implementations may support
different strings; they must agree on an exact string's meaning to interoperate,
not infer semantics from its spelling. The profile defines the structural rules
and keeps structural/cryptographic validity separate from verifier admission.
Acceptance may rest on explicit trust, a human procedure, or implemented checks;
recognizing a marker is not itself an acceptance decision. An incompatible
change to what acceptance authorizes needs a different string, without any
prescribed version syntax.

A feature implementation must address how the departure matches the consumer's
request and what justifies acceptance. Signing a marker authenticates it, but
does not by itself solve request matching or make a departure safe to accept.

## Execution Boundaries

`buildType` defines the build template and its parameters. `builder.id` instead
identifies the execution trust boundary, including the systems and people relied
upon to execute the build and report it faithfully. There is no umbrella "laut
builder" identity covering all installations or security modes.

As required by SLSA, modes with different security attributes MUST have different
builder IDs. In the current key-derived-ID profile this requires separate keys;
an annotation or critical marker cannot substitute for that separation.
Authentication of the signer-builder pair remains distinct from verification of
the properties claimed about the execution.

## Standards Basis

- [SLSA v1.2 BuildDefinition and externalParameters](https://slsa.dev/spec/v1.2/build-provenance#builddefinition): the build type defines the interface; verifiers should reject unknown or unexpected external parameters.
- [SLSA v1.2 Builder](https://slsa.dev/spec/v1.2/build-provenance#builder): execution trust boundaries, security modes, and signer-builder pairs.
- [SLSA v1.2 extension fields](https://slsa.dev/spec/v1.2/build-provenance#extension-fields): ignorable extensions must not alter other fields' meanings.
- [in-toto parsing rules](https://github.com/in-toto/attestation/blob/main/spec/v1/README.md#parsing-rules): open fields and monotonic interpretation.
- [in-toto DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md): custom sibling identity schemes with explicit semantics and encodings, including immutable references; no universal SHA-256 identity is implied.
