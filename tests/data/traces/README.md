# Build Evidence Fixtures

`signatures/<input-hash>` contains Sigstore v0.3 bundles as JSON Lines. The
directory name is historical; runtime verification accepts only the new format.

The 314 claims were migrated from commit `4ee196c`. Each original JWS signature
was verified with its corresponding checked-in builder test key before the
input/output claim was mapped to the SLSA profile and re-signed with Ed25519ph.
The input hashes, output paths, NAR hashes, and castore entry bytes were retained.
Invocation IDs are the first 16 bytes of SHA-256 of the original compact JWS,
encoded in lowercase hex, to make this fixture migration deterministic.

Debug preimages retain the resolved ATerm; obsolete JSON-preimage debug data
was removed. The tracked builderA lookup maps now contain decoded in-toto
statements. These are test claims, not evidence from newly executed builds.

The profile is documented in `docs/slsa-provenance-v1.md`. Integration tests use
these local fixtures and never query public infrastructure.

`consolidate.py` inspects bundle collections without signature verification.
Its groups are based on unauthenticated hints, not trusted signer identities.
The historical MinIO-internals extractor is only for old archived test data;
export new bundle objects through the storage service's normal object API.
