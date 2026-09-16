# Sigstore Migration Plan

Status: initial implementation completed and tested locally, 2026-09-16. This document records
the agreed scope, implementation order,
and upstream references so that subsequent changes can be reviewed against them.

## Progress

- `001f8eb`: committed this plan before implementation.
- `4544a2d`: replaced JWS with the documented managed-key SLSA/DSSE profile,
  JSON Lines cache collections, migrated fixtures, and debug extraction.
- `c0f8bfd`: added Rekor v2 proof validation, CLI requirements, and private VM
  interoperability tests.
- Rekor v2 submission and offline verification are implemented. Publishers
  verify proofs before publication; `--require-log` adds the initial global
  admission criterion. Ed25519 and P-256 checkpoint keys are supported.
- `small-sigstore-sign` and `small-sigstore-verify` passed privately for CA and
  IA multi-output builds, including independent sigstore-go verification and
  adversarial cases. The verifier VM has no log VM or public network access.
- Interoperability required SSH-style DSSE key hints. Authority and builder
  identity remain derived from the actual key's full SPKI fingerprint.
- The independent oracle uses sigstore-go v1.3.0, not Rekor's older v1.1.4
  dependency, to check the PAE-to-log binding. Its checkpoint name handling
  drops URL ports/paths, so interoperability tests use a default-port log URL.
- Final workspace tests passed with and without default features (78 tests in
  each configuration). All 314 migrated fixture bundles verify under their
  respective cache keys.
- Both package builds, the private-log sign/verify checks, and the existing
  small CA and IA sign/verify checks passed. No medium or large VM tests were
  run locally. The private-log check also exercises the debug-preimage probe.
- A temporary verification-only source-content edit left the sign-only
  derivation unchanged; the temporary edit was removed afterward.
- The JSON Lines inspection utility extracted all 314 fixture statements into
  two hint groups. Its grouping is explicitly unauthenticated.

The implementation uses `ed25519-dalek` 2.1.1, `p256` 0.13.2, and the existing
SHA-2/serde stack in Rust. It implements the small DSSE and RFC 6962/checkpoint
protocol surface directly rather than relying on incomplete high-level Rust
Sigstore verification. Independent sigstore-go tests validate interoperability;
they do not constitute a security audit or a production-scale benchmark.

Known initial limits are documented in [the profile](slsa-provenance-v1.md):
managed Ed25519ph build keys, Ed25519/P-256 checkpoint keys, explicit local log
trust, no trusted timestamps/validity-window policy, and explicit failure on
duplicate-submission HTTP 409 rather than online proof recovery. The private
tests confirm the duplicate response and do not generate a replacement claim.

## Goals and Decisions

- Replace the custom compact JWS format outright. Do not add legacy JWS
  acceptance; regenerate the repository's fixtures instead.
- Describe completed builds using an in-toto Statement v1 with a SLSA Provenance
  v1 predicate, signed in a DSSE envelope and distributed in a Sigstore Bundle.
- Record only the aggregate resolved input hash, not individual dependency
  identities, the unresolved dependency graph, or an original flake/source
  identity. The same resolved request can arise from different unresolved builds.
- Preserve resolved-input-hash computation, CA and synthetic-CA-from-IA semantics,
  named output claims, and the existing consensus calculation.
- Keep keys narrowly scoped. Evidence production must remain independent of
  verification-time aggregation and policy. Neither signatures nor builder IDs
  are an aggregation mechanism.
- Retain signed Nix implementation/version metadata so verifiers can eventually
  reject evidence involving, for example, vulnerable sandbox implementations.
- Distinguish individual claimed build attempts with random invocation IDs.
  Multiple attempts from one signer do not create additional independent votes.
- Reuse existing Nix cache keyfiles and Ed25519 key material, but use Ed25519ph
  for the new DSSE signatures. Existing Nix cache signatures remain unchanged.
- Use the same statement, envelope, and bundle machinery for direct and logged
  evidence. Logging adds verification material; it does not replace the build
  signer's signature or authorize otherwise untrusted signers.
- Store one object per resolved input hash at `traces/<resolved-input-hash>`.
  Each line is one standard Sigstore Bundle, encoded as JSON Lines.
- Keep ordinary verification to one cache GET per input hash per configured
  cache, with no mandatory log lookup, directory listing, or manifest fetch.
- Make the first log requirement verification-wide. Eventually it belongs in
  the trust model as a criterion on the signer; do not pull in the untested
  Nix-module-shaped configuration interface now.
- Exercise transparency services privately in NixOS VM tests. Tests must not
  submit entries to, or otherwise depend on, public Sigstore infrastructure.
- Do not clone research repositories as part of this work. Record relevant
  sources and selected dependency revisions here or in the resulting profile.
- Run only small VM tests locally, including the focused private-log checks.
  Medium and large VM tests are explicitly excluded from local execution.

## Deferred Work

- Pre-execution/start attestations, paired start/completion events, execution
  gates, and detecting unfinished builds. This was considered and explicitly
  deferred because it needs additional payload and orchestration work.
- Keyless signing, Fulcio/OIDC integration, certificate verification workflows,
  key rotation/revocation, and automated trust-root distribution.
- Hardware-attestation generation or verification. Standardized evidence should
  leave room for this later, but provenance does not itself prove execution on
  measured hardware.
- Log monitoring, witnessing policy, cross-checkpoint consistency tracking,
  cache completeness proofs, and analysis of other log entries.
- A new policy language, Nix-version selection UI, or the pending Nix-module UI.
- Alternative cache directory layouts, per-bundle object storage, and a separate
  ingestion/materialization service.
- Production operation of cache.nixos.org or a public log. This migration should
  support that deployment, not perform it.

## Representation

The proposed hierarchy is:

```text
traces/<resolved-input-hash>       one JSON Lines object
  Sigstore Bundle                one build signature per bundle
    DSSE envelope
      payloadType: application/vnd.in-toto+json
      payload: exact serialized statement bytes, base64 encoded
        _type: https://in-toto.io/Statement/v1
        subject: named output artifacts
        predicateType: https://slsa.dev/provenance/v1
        predicate: laut's documented SLSA build profile
      signature: Ed25519ph over DSSE PAE
    verification material
      public-key hint
      log entry, inclusion proof, signed checkpoint (logged mode)
```

Target Bundle v0.3, with media type
`application/vnd.dev.sigstore.bundle.v0.3+json`. SLSA's current specification is
v1.2, but the provenance predicate URI remains `https://slsa.dev/provenance/v1`.
Using these schemas does not establish or claim a SLSA security level.

DSSE does not canonicalize JSON. It authenticates the payload type and exact
payload bytes through Pre-Authentication Encoding (PAE). Preserve those bytes
through signing, logging, and verification. Rekor entry canonicalization is a
separate operation and must not be confused with payload serialization.

### Payload Mapping

| Current information | Planned location or treatment |
| --- | --- |
| `in.rdrv_aterm_ca` | `buildDefinition.externalParameters.resolvedInputHash`, interpreted by the documented build type |
| Input representation/version | Versioned `buildDefinition.buildType` URI |
| Individual dependency identities | Omitted; do not populate `resolvedDependencies` with them |
| `in.from_ia` | Required distinction in the laut profile; decide its precise encoding before implementation |
| `out.nix.<name>` | Named statement subjects, with explicit Nix output identity and metadata semantics |
| `out.castore-entry.<name>` | Precisely specified representation associated with that named output, not mislabeled as a NAR digest |
| Builder execution trust boundary | `runDetails.builder.id` |
| `builder.nix_flavor` and `builder.nix_version` | `runDetails.builder.version` |
| `builder.rebuild_id` | `runDetails.metadata.invocationId`, using a larger random identifier |
| `builder.store_root` | Preserve its meaning; specify whether implicit in the build type or explicitly recorded |
| Optional signed debug preimage | Debugging byproduct, kept separate from the regular build-input interface |

The profile must settle these representation details without changing the
underlying evidence semantics:

- Define the input hash's algorithm and encoding accurately. A Nix derivation
  store-path digest is not simply `sha256(ATerm)`.
- Specify output digest algorithms, representations, encodings, output names,
  store paths, and castore entries. Do not label a structured castore entry as
  an ordinary digest or conflate a rewritten IA output with its original bytes.
- Make the CA/IA distinction mandatory to interpret and accept a claim. It
  must not depend on an ignorable annotation that changes another field's meaning.
- Choose and document the build-type and builder-ID URI conventions. A builder
  ID describes an execution trust boundary, not a software release or an
  independent source of authority. Do not silently broaden signer scope or
  combine signers that claim the same builder ID.
- Keep implementation/version metadata authenticated and available after
  verification, even though this migration adds no version-policy interface.
- Give each newly produced claim a sufficiently large random invocation ID.
  Reuse the same statement and ID on publication retries. IDs distinguish
  claimed attempts; they do not prove distinct executions or full disclosure.

## Publication and Verification

### Direct and Logged Publication

Construct and sign the statement once. In direct mode, package it with a
public-key hint. In logged mode, submit its signing metadata to the configured
Rekor v2 service, verify the response, and attach the returned verification
material to the same bundle.

Rekor v2's `hashedrekord` records the signature, verifier material, and the hash
of the DSSE PAE bytes using the signing scheme's externalized hash. It does not
store the full statement. Pure Ed25519 is unsuitable for that construction;
Ed25519ph is a different algorithm, not pure Ed25519 applied to a digest.

Logging failure must not silently publish direct-only evidence as a successful
logged operation. Require a valid inclusion proof and checkpoint, not just an
inclusion promise or a successful submission response. Exercise retry and
duplicate-submission behavior against the selected server version.

The cache's backing storage can also be the authoritative bundle archive.
Rekor alone cannot reconstruct it. Retain original bundles rather than creating
a second, laut-specific representation of their claims or receipts.

For collection updates, preserve existing entries, deduplicate publication
retries, and use conditional writes: `If-None-Match: *` for creation and
`If-Match` with the observed ETag for replacement. On conflict, re-read and merge.
Define deduplication separately from invocation identity; different proofs of
the same signature must never create extra consensus votes.

### Evidence Admission

The verifier must check the expected Bundle/DSSE/Statement/predicate/build-type
formats and the mandatory fields of the laut profile. Authenticate the exact
payload bytes, then match the signed input hash and CA/IA regime to the local
request and admit the named output claim atomically.

DSSE `keyid` and the bundle's key hint are unauthenticated routing hints. Follow
the bundle's hint-consistency rules, but derive the counted signer authority
from the configured key that actually verifies the signature, not an asserted
name or builder ID. Never trust a key just because it occurs in log material.

In logged mode, additionally verify:

- The selected entry kind/version and supported signing suite.
- The binding between the log entry and the envelope's PAE digest, signature,
  and actual verification key.
- The checkpoint signature and expected log identity against explicitly
  configured log trust.
- The Merkle inclusion path, index, and tree size against that authenticated
  checkpoint. Keep the tree hash distinct from the signing scheme's hash.

Choose one well-specified entry-binding implementation, rather than fallback
paths. Retaining the server's canonicalized entry bytes and validating all
bindings avoids inventing another receipt format.

The initial verification-wide requirement is either signature-only or
signature-plus-log. Signature-only can accept a logged bundle based on its valid
build signature. Required log evidence cannot be stripped or made invalid to
downgrade acceptance. Structure the check so a future signer criterion can
supply the requirement without changing the consensus algorithm.

The managed-key profile does not assert a trusted signing timestamp. Rekor v2
does not supply a trusted integration timestamp; certificate/time-based
workflows remain deferred. Unknown or unsupported security-relevant formats
must not become accepted evidence.

Inclusion proves membership in a signed tree. It does not prove that the cache
returned every matching claim, that the producer disclosed every build, or that
the log never equivocated. No full log copy is required for ordinary
verification. Lookup request count stays constant in log size, while inclusion
proof size and hashing work are `O(log N)`.

## Implementation Order

### 1. Profile and Interoperability Gate

- [x] Finalize the payload mapping and required fields. The fixture corpus and
  `vm-tests/small-sigstore.nix` provide executable CA, IA, multi-output, direct,
  logged, and debug examples; exported VM bundles are available for inspection.
- [x] Pin the Rekor v2 test server and independent interoperability tooling.
- [x] Demonstrate Ed25519ph DSSE signing using existing Nix key material.
- [x] Verify direct and logged bundles using an independent implementation,
  against a private log and explicit test trust roots only.
- [x] Evaluate Rust components for the required managed-key, DSSE, checkpoint,
  and inclusion-proof functionality before committing to dependencies.

Use `sigstore-go` as an interoperability reference, not an assumed production
runtime dependency. The inspected `sigstore-rs` high-level bundle verifier has
unimplemented log-proof checks; its presence is not evidence that those checks
are performed. Reassess the exact revisions selected for implementation.

### 2. Shared Format and Direct Signing

- [x] Replace `laut-sign/src/sign/jws.rs` with the shared statement/envelope/bundle
  implementation and update `laut-sign/src/sign.rs`.
- [x] Preserve existing keyfile parsing and hashing behavior; enable the chosen
  Ed25519ph implementation explicitly, without a pure-Ed25519 fallback.
- [x] Generate invocation IDs once per new claim and preserve optional metadata.
- [x] Keep common format/signing code on the sign side and verification-only
  dependencies in `laut-verify`, preserving sign-only build isolation.
- [x] Add payload, encoding, signing, and malformed-input unit tests.

### 3. Cache and Verifier Migration

- [x] Migrate `laut-sign/src/http_cache.rs` to JSON Lines bundle collections with
  conditional merge updates and explicit retry/deduplication tests.
- [x] Update retrieval/admission code to consume bundles and return verified
  signer facts. The Backend contract remains raw bytes; no new transport API.
- [x] Preserve threshold, divergence/convergence, and atomic multi-output rules.
- [x] Migrate debug corpus decoding and fixtures without adding JWS compatibility.
- [x] Test that input-hash mismatch, regime mismatch, malformed claims, and
  unauthenticated key hints cannot introduce accepted facts.

### 4. Transparency Integration

- [x] Implement submission to explicitly configured Rekor v2 endpoints and
  verification of returned entry bindings, proofs, and checkpoints.
- [x] Add explicit log trust configuration and the initial verification-wide
  log requirement in `laut-cli`; do not add the pending policy UI.
- [x] Keep the log criterion at the signer-admission boundary for future
  signer-specific requirements, without treating logs as build-signer votes.
- [x] Verify that cache-based validation needs no log connection or implicit
  public trust-root download.
- [x] Test failures, bounded submission retries, duplicate entries, proof stripping,
  wrong keys/logs, and mismatched or tampered logged content.

### 5. Private NixOS VM Tests

- [x] Package the pinned Rekor v2 POSIX server, using a local test signing key,
  local filesystem state, and a NixOS/systemd service. No Docker or cloud backend
  is needed for this test topology.
- [x] Add a focused log-signing VM test with cache, builder, and log nodes, using
  the existing `vm-tests/test-template.nix` structure where appropriate.
- [x] Add a verification test consuming its exported cache without a running
  log, preserving the existing sign/verify test split and rebuild isolation.
- [x] Use test-only build/log keys and explicit endpoints and trust material.
  Disable external network access during test execution so public-service
  defaults or fallback paths fail instead of contacting public infrastructure.
- [x] Exercise real Ed25519ph signing, real log submission, and offline proof
  verification. Cover direct acceptance and rejection under a logged requirement.
- [x] Tamper the PAE binding, signature, entry verifier, proof, checkpoint, log
  identity, and required evidence; assert rejection without changing consensus.
- [x] Keep quick Rust tests offline using local fixtures. Cover relevant
  conformance failure classes and use an independent verifier rather than
  running a public-service-dependent suite.
- [x] Record sample bundle size/material overhead and operation timings in the
  private VM test log. These tiny examples are not production-scale benchmarks.

Source/dependency downloads to build the test closure are distinct from test
execution. Test execution must neither read public Sigstore services nor submit
public entries. Pre-execution/start-record tests are not part of this scope.

### 6. Migration Verification and Documentation

- [x] Regenerate affected Rust fixtures and update VM scripts and user-facing
  format/CLI documentation. Keep a traceable relationship to existing scenarios.
- [x] Run `nix develop -c cargo test --workspace`.
- [x] Run `nix develop -c cargo test --workspace --no-default-features`.
- [x] Run `nix build .#laut .#laut-sign-only` (with `--no-link --cores 4`).
- [x] Run `small-sigstore-verify` (including its sign dependency and debug probe),
  `small-ca-verify`, and `small-ia-verify` (including their sign dependencies).
  Larger VM checks are deliberately not run locally.
- [x] Confirm verification-only edits do not change the sign-only derivation.
- [x] Record actual dependency versions, interoperability results, and any
  differences between specification text and implementation behavior.

New Rust source files must be added with `git add -N` for the Nix source filter.
Do not commit or modify unrelated worktree changes as part of the migration.

## Upstream References

These are research sources, not a list of dependencies to add. Revisions below
were observed during the design discussion and are reference snapshots, not
automatic choices of production dependency versions.

### Primary Sources

| Repository | Role and important paths | Observed revision |
| --- | --- | --- |
| [secure-systems-lab/dsse](https://github.com/secure-systems-lab/dsse) | PAE protocol, envelope rules, test vectors: `protocol.md`, `envelope.md`, `implementation/` | `1d3370f62565bca041e97c8310b873ac340edc2e` |
| [in-toto/attestation](https://github.com/in-toto/attestation) | Statement, resource descriptors, digest semantics: `spec/v1/` | `fd2609c16bcb0ac53443e2b4612977f997e8f9a5` |
| [slsa-framework/slsa](https://github.com/slsa-framework/slsa) | Provenance semantics and build-type requirements: `spec/build-provenance.md` on `releases/v1.2`; [rendered specification](https://slsa.dev/spec/v1.2/build-provenance) | `ae7fc76215004e8fae250c877eff8919bf048e3b` |
| [sigstore/protobuf-specs](https://github.com/sigstore/protobuf-specs) | Bundle, log entry, algorithms, trust schemas: `protos/sigstore_bundle.proto`, `sigstore_rekor.proto`, `sigstore_common.proto`, `sigstore_trustroot.proto` | `d615235697f53603ef41ebf6e582582e4e0ddd90` |
| [sigstore/architecture-docs](https://github.com/sigstore/architecture-docs) | Client verification, Rekor v2, algorithm registry: `client-spec.md`, `rekor-v2-spec.md`, `algorithm-registry.md` | `30974174a4aa05a2c73509a1d4391bd44c7eb764` |
| [sigstore/rekor-tiles](https://github.com/sigstore/rekor-tiles) | Real log and local deployment: `api/proto/rekor/v2/`, `pkg/types/hashedrekord/`, `cmd/rekor-server/posix/`, `CLIENTS.md` | `eb0f2e566b4248bf0638115a08c07228ebbdcdc9`; also inspected release `v2.3.0` |
| [sigstore/sigstore-go](https://github.com/sigstore/sigstore-go) | Independent managed-key bundle/signing/verification reference: `pkg/bundle/`, `pkg/sign/`, `pkg/verify/` | `c97e21803801b4acaf59941cb4327d03e8a2da38` |
| [sigstore/sigstore-rs](https://github.com/sigstore/sigstore-rs) | Candidate Rust components, not yet an adequate high-level verifier for this task: `src/bundle/verify/verifier.rs` contains log verification TODOs in this snapshot | `038e36aefac21dd4ae608cda33736a494250fd1f` |

### Supporting and Deferred Sources

| Repository | Relevance or reason not to adopt now |
| --- | --- |
| [sigstore/sigstore-conformance](https://github.com/sigstore/sigstore-conformance) | Relevant adversarial and managed-key test cases; use local fixtures/private services, not its public-service test defaults |
| [C2SP/C2SP](https://github.com/C2SP/C2SP) | Signed notes and transparency checkpoints; witnessing/consistency protocols are future context, not current scope |
| [transparency-dev/tessera](https://github.com/transparency-dev/tessera) | Rekor's tile-backed log implementation and POSIX/cloud operation; prefer the existing Rekor service over a custom log personality |
| [transparency-dev/merkle](https://github.com/transparency-dev/merkle) | RFC 6962 Merkle implementation and proof behavior used by Rekor; useful verification reference |
| [sigstore/rekor](https://github.com/sigstore/rekor) | Historical v1 behavior and fixtures; do not add v1 support without a concrete requirement |
| [sigstore/cosign](https://github.com/sigstore/cosign) | Secondary interoperability/CLI reference; OCI storage and identity-centric defaults are not our architecture |
| [project-oak/oak](https://github.com/project-oak/oak) | `docs/tr/README.md` and remote-attestation documentation show in-toto/Rekor composition with hardware-attestation verification; future work only |
| [in-toto/in-toto](https://github.com/in-toto/in-toto) | `in-toto-record start/stop` is a local unfinished-link workflow, not a pre-execution transparency guarantee; lifecycle feature deferred |
| [sigstore/fulcio](https://github.com/sigstore/fulcio), [sigstore/root-signing](https://github.com/sigstore/root-signing) | Certificate identity and public trust distribution are out of scope; private tests must not rely on them |
| [edgelesssys/contrast](https://github.com/edgelesssys/contrast) | Broader confidential-workload context, not a required component or an established solution for this build-evidence migration |
| [mschwaig/snix](https://github.com/mschwaig/snix) | Existing pinned Nix hashing, key parsing, and castore representation; preserve these semantics, do not bump incidentally |

The in-toto layout/link workflow and SBOM formats are not required to adopt the
in-toto Statement and SLSA predicate. Keep those projects separate from the
minimal format, signing, log, and verification components selected here.
