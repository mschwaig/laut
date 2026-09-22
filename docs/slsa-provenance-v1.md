# Laut SLSA Provenance v1

This profile describes one completed Nix build attempt, not an aggregation of
attempts or an unresolved dependency graph. The signed statement maps one
complete resolved request to named output resources, each with sibling identity
representations. SLSA schema compliance does not claim a SLSA security level.

This profile applies laut's original [format design principles](design.md):
independent producer/consumer evolution, incremental verification of evidence,
and coexisting representations. `criticalFeatures` is part of the contract of
both build types below.

## Envelope

Use Sigstore Bundle v0.3 (`application/vnd.dev.sigstore.bundle.v0.3+json`) with
`dsseEnvelope`, payload type
`application/vnd.in-toto+json`, and one Ed25519ph signature (RFC 8032, SHA-512,
empty context) over DSSE PAE. Serialize the statement once; verification uses
those exact bytes, not canonicalized JSON. Reject duplicate JSON object keys.

The initial profile supports managed Ed25519 keys only. Existing Nix keyfiles
and key material are reused; signatures are newly generated. Public-key hints
use the SSH `SHA256:<base64-without-padding>` fingerprint convention used by
go-securesystemslib's DSSE adapter: hash the SSH Ed25519 public-key encoding,
not DER SubjectPublicKeyInfo. Producers use the same hint in the envelope and
verification material. Hints are not authorities:
verification derives identity from the configured key that verifies the claim.

## Build Definition

The statement `_type` is `https://in-toto.io/Statement/v1` and `predicateType`
is `https://slsa.dev/provenance/v1`. Under `predicate`,
`buildDefinition.externalParameters` defines only:

- `resolvedInput`: a required ResourceDescriptor for the complete resolved
  request, with a nonempty `digest` map and optional ResourceDescriptor metadata.
  Every entry identifies the same complete request, not one of its dependencies.
- `criticalFeatures`: a set represented as an array of unique strings, declaring
  departures from baseline assumptions that are unsafe to ignore. The initial
  signer emits `[]`.

Reject unknown external parameter fields. `buildType` defines this parameter
interface, following [SLSA v1.2 externalParameters](https://slsa.dev/spec/v1.2/build-provenance#builddefinition).

The `digest` map is a DigestSet: nonempty scheme keys with nonempty string values.
Unknown-only maps are structurally valid; no known scheme is universally
required. Scheme keys are compared exactly.

The current producer emits `resolvedInput.digest["aterm"]`:
the existing 32-character Nix-base32 digest of the resolved derivation store
path. This scheme uses the existing Nix text-store-path construction, including
the resolved ATerm, references, store root, and derivation name, followed by
Nix's 20-byte digest compression. It is not SHA-256 of the ATerm alone.
Dependencies are already resolved to content identities before hashing; the
hash neither specifies nor commits to the original unresolved derivation graph.
Verifiers reconstruct the request from their own graph and candidate resolutions.

Nix store paths in this profile use `/nix/store`. Changing the store-root semantics
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

### Critical Features and Admission

The full signed field is
`predicate.buildDefinition.externalParameters.criticalFeatures`. Each marker is
an opaque string compared exactly. Even `""` is a structurally valid marker,
not an empty set or a supported feature.

Absent, `null`, and `[]` all mean the empty set, following
[SLSA parsing rules](https://slsa.dev/spec/v1.2/build-provenance#parsing-rules).
Otherwise the field must be an array of strings without duplicates; wrong types,
non-string elements, and duplicate strings are malformed. Array order has no
semantic significance.

Producers MUST truthfully mark departures that would be unsafe to interpret as
baseline claims. Optional evidence that leaves the baseline claim intact does
not need a marker merely because some consumers do not understand it.

Shared format validation, signing, and cryptographic verification accept any
well-formed marker set structurally. This does not authorize it for reasoning.
Before inserting any facts, the actual verifier separately checks the signed
set: an unknown or unaccepted marker makes that entire atomic output claim
ineligible. Other claims, including claims in the same cache object, remain
eligible for their own checks. The current laut verifier rejects all nonempty
sets.

The Nix resolved input hash and hence its trace lookup do not commit to
the marker list. The signature covers the list separately, and admission must
check it even when the input hash matches.

## Subjects

Each subject is one logical named output ResourceDescriptor, with a unique
nonempty `name` and a nonempty `digest` map following the same DigestSet rules
as `resolvedInput`.

The current producer emits these sibling schemes in each subject's `digest`:

- `nix-ca-store-path`: the output's absolute CA or synthetic CA `/nix/store` path.
- `nix-nar-sha256`: lowercase 64-character hexadecimal SHA-256 of the NAR bytes
  (after rewriting for synthetic IA). Producers convert the existing Nix-base32
  NAR hash to hex.
- `snix-castore-entry`: base64 of the existing empty-root-name castore Entry
  protobuf for that output.

Other schemes are allowed as equal siblings. `annotations.laut_output` retains
other Nix derivation output metadata, excluding `path` and `hash`, which have
identity representations above. `mediaType` is optional; the current producer
omits it.

These custom schemes use the standard
[in-toto DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)
extension mechanism, including immutable references. Every scheme must define
what it identifies and how it is encoded.

### Sibling Example

This fragment illustrates sibling maps for the complete request and one output.
The zero hashes and `example-request` scheme are illustrative.

```json
{
  "predicate": {
    "buildDefinition": {
      "externalParameters": {
        "resolvedInput": {
          "digest": {
            "aterm": "00000000000000000000000000000000",
            "example-request": "immutable-request-reference"
          }
        },
        "criticalFeatures": []
      }
    }
  },
  "subject": [
    {
      "name": "out",
      "digest": {
        "nix-ca-store-path": "/nix/store/00000000000000000000000000000000-example",
        "nix-nar-sha256": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    }
  ]
}
```

### Current Admission

Before inserting facts, the current verifier requires:

- Authentication, required log checks, and critical-feature admission.
- A well-formed `aterm` identity matching the locally
  reconstructed request hash and the cache lookup hash.
- The matching CA/IA build type.
- A usable `nix-ca-store-path` for every subject.

Failure excludes the whole claim, not just an unusable output or other claims
in the cache collection.

## Supplementary Evidence

Unknown signed metadata, annotations, and digest keys are retained,
not stripped when admitting a claim. Subject to the structural requirements
above, consumers may ignore what they do not use. This follows the
[in-toto parsing rules](https://github.com/in-toto/attestation/blob/main/spec/v1/README.md#parsing-rules)
and [SLSA extension rules](https://slsa.dev/spec/v1.2/build-provenance#extension-fields):
ignorable extensions must not change the meaning of another field. The closed
`externalParameters` interface and its checked `criticalFeatures` set are not
ignorable extensions.

## Run Details

`builder.id` is `urn:laut:builder:sha256:<fingerprint>`, where the fingerprint
is SHA-256 of the signing key's DER SubjectPublicKeyInfo. It identifies the
execution trust boundary. This managed-key profile requires the ID to match the
verifying key, establishing the signer-builder pair explicitly.
Use separate keys for independently trusted execution boundaries. Under
[SLSA's builder rules](https://slsa.dev/spec/v1.2/build-provenance#builder), modes
with different security attributes MUST have different builder IDs. Since this
profile derives IDs from keys, those modes require separate keys. Neither an
annotation nor a critical marker substitutes for that separation.

`builder.version` may contain `nixFlavor`, `nixVersion`, and other string-valued
component versions.

`metadata.invocationId` is a random 128-bit value encoded as 32 lowercase hex
characters. It identifies a claimed attempt, not an independently verified
execution or a guarantee of complete disclosure. Publication retries preserve
the original statement and ID.

When explicitly requested for diagnostics, `byproducts` contains a descriptor
named `laut-debug-preimage`, media type `application/json`, with base64 `content`
holding the debugging JSON (derivation name/path and resolved ATerm preimage).
It is not emitted by default. Debug corpus inspection is deliberately
unauthenticated and does not admit claims into verification.

## Storage and Logging

Trace collections are indexed at `traces/<scheme>/<hash>`. The current signer
and verifier use `traces/aterm/<hash>`, where `hash` is the
corresponding value in the resolved input's digest map. Each collection is one
JSON Lines object, one complete bundle per line. Conditional create/replacement
preserves concurrent contributions.

Cache URLs name the cache root. The debug corpus uses that same root and scans
`traces/aterm/`, requiring a directory listing for HTTP caches.

Direct bundles have no `tlogEntries`. Logged bundles attach verified Rekor v2
`hashedrekord` v0.0.2 evidence binding the SHA-512 digest of the DSSE PAE,
Ed25519ph signature, and public key to a signed checkpoint via an inclusion
proof. The log's Merkle tree uses RFC 6962 SHA-256, independently of that SHA-512.

Log keys and identities are configured independently of trusted build signers.
A log does not grant build authority. A verification-wide logged requirement
cannot be downgraded by removing proof material. Ordinary verification is offline
with respect to the log.

The cache/archive must retain the full bundles: Rekor records commitments, not
statement payloads. Inclusion proves membership in a signed tree, not complete
cache results or global non-equivocation. No trusted signing time is asserted
in this managed-key profile.

## Log Configuration

`--trusted-root` reads a local Sigstore TrustedRoot v0.1 JSON file. The `tlogs`
entries provide `baseUrl`, `hashAlgorithm: "SHA2_256"`, and `publicKey` with
base64 DER `rawBytes` and `keyDetails`. Supported checkpoint key details are
`PKIX_ED25519` (pure Ed25519 checkpoints) and `PKIX_ECDSA_P256_SHA_256`
(ASN.1 DER ECDSA signatures). They are independent of the Ed25519ph build key.

Configure the log's checkpoint origin as its scheme-less `baseUrl`, without a
trailing slash. For Ed25519 logs, the full checkpoint key ID is SHA-256 of
`origin || LF || 0x01 || raw_public_key`. For P-256 it is SHA-256 of DER SPKI,
following Rekor's convention. Any supplied `logId` or `checkpointKeyId` must
match. Checkpoint signatures use the first four bytes of that ID as their hint.
The log's signing keys must be trusted out of band, never learned from the
returned bundle or fetched from the submission endpoint.

This implementation uses the configured log keys as accepted authorities; it
does not enforce time-based key validity windows without a trusted timestamp.
Only the `tlogs` part of TrustedRoot is used. Certificate authorities, identity
providers, timestamp authorities, and automatic updates are not enabled.

Submission retries transient errors with the same signature and statement.
An HTTP 409 duplicate-submission conflict is surfaced as an error rather than
silently re-signing or attempting online proof recovery. The returned proof
must be validated before a logged bundle is published. Cache publication
retries preserve the same complete bundle and use conditional writes.

The private interoperability tests pin Rekor v2.3.0 and sigstore-go v1.3.0.
The latter independently reconstructs the logged entry from the bundle,
while laut verifies bindings against the persisted entry bytes. Tests use a
default-port log URL: sigstore-go v1.3.0 derives note names using `Hostname()`
and does not preserve non-default ports or path components. Laut retains them
in its explicitly configured origin. This is a tooling interoperability limit,
not a reason to accept a checkpoint from an unexpected origin.
