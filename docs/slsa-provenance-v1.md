# Laut SLSA Provenance v1

This profile describes one completed Nix build attempt, not an aggregation of
attempts or an unresolved dependency graph. The signed statement maps an
aggregate resolved input hash to named outputs. SLSA schema compliance does not
claim a SLSA security level.

## Envelope

Use Sigstore Bundle v0.3 with `dsseEnvelope`, payload type
`application/vnd.in-toto+json`, and one Ed25519ph signature (RFC 8032, SHA-512,
empty context) over DSSE PAE. Serialize the statement once; verification uses
those exact bytes, not canonicalized JSON. Reject duplicate JSON object keys.

The initial profile supports managed Ed25519 keys only. Existing Nix keyfiles
and key material are reused; signatures are newly generated. Public-key hints
are the lowercase SHA-256 of DER SubjectPublicKeyInfo, and producers use the
same hint in the envelope and verification material. Hints are not authorities:
verification derives identity from the configured key that verifies the claim.
Key aliases and repeated evidence must not multiply consensus votes.

## Build Definition

The statement `_type` is `https://in-toto.io/Statement/v1` and `predicateType`
is `https://slsa.dev/provenance/v1`. `buildDefinition.externalParameters` contains
exactly one field, `resolvedInputHash`, with the 32-character Nix-base32 digest
of the resolved derivation store path. No `resolvedDependencies` are emitted.

This hash is the existing Nix text-store-path construction, including the
resolved ATerm, references, store root, and derivation name, followed by Nix's
20-byte digest compression. It is not SHA-256 of the ATerm alone. Dependencies
are already resolved to content identities before hashing; the hash neither
specifies nor commits to the original unresolved derivation graph. Verifiers
reconstruct the request from their own graph and candidate resolutions.

All paths in this profile use `/nix/store`. Changing the store-root semantics
requires another build type. The following distinct build types make the
CA/IA distinction mandatory rather than an ignorable annotation.

### CA

Build type: `https://github.com/mschwaig/laut/blob/main/docs/slsa-provenance-v1.md#ca`

Execute the resolved, floating content-addressed Nix derivation. Its output
identities are the realized Nix store paths and the contents serialized as NARs.
Use the existing resolved-ATerm hashing algorithm in
`laut-sign/src/constructive_trace.rs`.

### Synthetic IA

Build type: `https://github.com/mschwaig/laut/blob/main/docs/slsa-provenance-v1.md#synthetic-ia`

Execute an input-addressed derivation, then describe its synthetic CA-equivalent
request and outputs using the existing IA closure rewriting algorithm. Replace
dependency paths with synthetic CA paths and own output paths with placeholders
when computing the input hash. Output subjects describe the rewritten contents,
not the original IA NAR bytes. CA and synthetic IA evidence are not interchangeable.

## Subjects

Each subject is one named output, with a unique nonempty `name` and:

- `digest.sha256`: lowercase hexadecimal SHA-256 of the NAR bytes (after
  rewriting for synthetic IA). Producers convert the existing Nix-base32 NAR
  hash; they do not hash the hash's textual representation.
- `mediaType`: `application/x-nix-nar`.
- `annotations.laut_storePath`: the output's absolute CA or synthetic CA path.
- `annotations.laut_castoreEntry`: base64 of the existing empty-root-name
  castore Entry protobuf for that output. This is a structured representation,
  not a NAR digest or a generic BLAKE3 digest.
- `annotations.laut_output`: other Nix derivation output metadata, excluding
  `path` and `hash`, which are represented above.

Laut requires the store path and castore representation; generic in-toto tools
may match the NAR digest alone, but that does not implement laut's resolution
and consensus semantics. A claim is an atomic output map; verifiers must not
mix outputs from different claims. The current reasoner uses store paths as
content identities. This format change does not make it verify local output
bytes where it previously only resolved provenance.

## Run Details

`builder.id` is `urn:laut:builder:sha256:<fingerprint>`, where the fingerprint
is SHA-256 of the signing key's DER SubjectPublicKeyInfo. It identifies the
execution trust boundary for which this narrowly scoped key is responsible,
not all installations of a Nix release. This managed-key profile requires the
ID to match the verifying key, establishing the signer-builder pair explicitly.
Use separate keys for independently trusted execution boundaries. A future
certificate/platform profile must define its own binding.

`builder.version` may contain `nixFlavor` and `nixVersion`, as well as future
string-valued component versions. These values are authenticated evidence and
are retained for policy evaluation; this migration adds no version-policy UI.

`metadata.invocationId` is a random 128-bit value encoded as 32 lowercase hex
characters. It identifies a claimed attempt, not an independently verified
execution or a guarantee of complete disclosure. Publication retries preserve
the original statement and ID. Additional invocations from a signer are not
additional signer votes.

When explicitly requested for diagnostics, `byproducts` contains a descriptor
named `laut-debug-preimage`, media type `application/json`, with base64 `content`
holding the debugging JSON (derivation name/path and resolved ATerm preimage).
It is not emitted by default. Debug corpus inspection is deliberately
unauthenticated and does not admit claims into verification.

## Storage and Logging

`traces/<resolvedInputHash>` is one JSON Lines object, one complete bundle per
line. Conditional create/replacement preserves concurrent contributions.
Direct bundles have no `tlogEntries`. Logged bundles attach verified Rekor v2
`hashedrekord` v0.0.2 evidence binding the SHA-512 digest of the DSSE PAE,
Ed25519ph signature, and public key to a signed checkpoint via an inclusion
proof. The log's Merkle tree uses RFC 6962 SHA-256, independently of that SHA-512.

Log keys and identities are configured independently of trusted build signers.
A log neither grants build authority nor supplies extra consensus votes. A
verification-wide logged requirement cannot be downgraded by removing proof
material. Ordinary verification is offline with respect to the log.

The cache/archive must retain the full bundles: Rekor records commitments, not
statement payloads. Inclusion proves membership in a signed tree, not complete
cache results or global non-equivocation. No trusted signing time is asserted
in this managed-key profile. Start events, certificate identities, monitoring,
and witnessing policy are outside this version's implementation scope.
