# Rust Dependency Update

This independent update starts from snix upstream
`b9dba2b9735798c13d73c08a1b08ae3c7bed7136` (2026-10-13), with laut's fork
helpers ported on the separate `fanfic-update-independent-20261017` branch.
The original `fanfic` branch is unchanged. Cargo and Nix both pin
`03c154ffb3c585835683219e1d901599a4cc87e6`.

## Dependency Decisions

The lockfile was updated using `cargo update`, not copied from snix. Direct
dependencies now use base64 0.23, rand 0.10, sha2 0.11, thiserror 2, and ureq 3,
alongside current compatible releases of the other workspace dependencies.

- `ed25519-dalek` stays on 2.x (2.2.0), matching the key types exposed by snix.
  Updating laut alone to 3.x would introduce incompatible signing key types.
- Snix's pinned hyper and tonic patches are repeated in the workspace root:
  Cargo does not inherit patches from dependencies. These retain upstream's
  HTTP/2 GOAWAY fixes. Only patches used by laut's dependency graph are included.
- Latest `tokio-util` adds another `LengthDelimitedCodec` encoder implementation.
  The fork explicitly converts encoded directory bytes to `Bytes`, fixing the
  resulting type ambiguity instead of downgrading the dependency.
- Trace preimages use the fork's `UnvalidatedDerivation`, not upstream's checked
  derivation builder, which would normalize output environment bindings and
  change the bytes being hashed.
- Ureq response bodies are read through its streaming API, preserving support
  for trace files larger than the new convenience readers' 10 MiB default limit.

## Castore Fingerprints

Upstream commit `2f4191a68cfe2ba1a8789790994b1e8e85e286dd` fixes double-counted
directory sizes. These sizes count entries, not bytes:

```text
old: 2 * immediate_entry_count + sum(child_directory_sizes)
new:     immediate_entry_count + sum(child_directory_sizes)
```

A directory containing two files therefore has size 2 instead of 4. The
serialized castore entry includes that size, so its fingerprint changes. When
directories contain other directories, their serialized child entries and
therefore directory digests can change too. Standalone regular-file and symlink
fingerprints, NAR serialization, and NAR hashes are unaffected by this size fix.

Laut uses only the new fingerprints. There is no dual-hash storage or fallback
lookup. Old signatures involving affected directory fingerprints do not match
newly computed fingerprints; regenerate those signatures with the updated
signer and verifier.

The raw ATerm hash helper also replaces its old bracket-counting input parser
with snix's full parser. It still hashes the original bytes, but correctly
collects input sources after nested input-output lists and rejects malformed or
trailing input. Existing CA fixture verification is covered by the Rust tests.

Edef has also discussed a future castore-v2 hashing scheme in the review of
[CL 30982](https://cl.snix.dev/c/snix/+/30982). That open serializer change is
intended to preserve current hashes; the future v2 redesign is not included in
this update. Basic symlink support already exists. No separate symlink-driven
hash change was identified in the upstream revision used here.

## Validation

The following checks passed with the updated lockfile:

- `cargo test --workspace --locked`: 79 tests passed.
- `cargo test --workspace --no-default-features --locked`: 79 tests passed.
- `nix build .#laut .#laut-sign-only --no-link`.
- `small-ca-sign` and `small-ca-verify` NixOS VM checks.
- `small-ia-sign` and `small-ia-verify` NixOS VM checks.
- `debug-probe` NixOS VM check, including the expected tampered-trace failure
  and structural diff marker.
- Changing verification-only source leaves the sign-only derivation unchanged.

The snix branch also passed nix-compat, laut-compat, and targeted castore tests.
Medium and large VM tests have not been run.
