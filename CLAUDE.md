# CLAUDE.md - Development Guide for laut

## Project Overview

`laut` is a Rust tool for creating and verifying cryptographic signatures for
Nix build traces. The signature format is JWS-based and supports configurable
trust models and verifiable provenance data for builds.

## Workspace layout

Cargo workspace at the repo root, three members:

- `laut-cli/` — the `laut` binary. Argument parsing + dispatch; the actual
  work lives in `laut-sign` and `laut-verify`.
- `laut-sign/` — sign-side orchestration + everything both sides need:
  derivation-path computation, content hashing, the constructive-trace
  resolved-input-hash routine, HTTP cache upload, JWS assembly, keyfile
  parsing, `nix` subprocess wrappers.
- `laut-verify/` — verify-side only: the orchestrator pipeline (under
  `src/orchestrator/`), the trust-model evaluator, signature verification,
  the hash-divergence debug probe.

The sign-only Nix build (`.#laut-sign-only`) drops `laut-verify/` from the
source tree entirely and passes `--no-default-features` to cargo, so the
resulting binary doesn't link against the verification code.

## Development environment

Enter the dev shell (cargo, rustc, protobuf, difftastic):
```bash
nix develop
```

Or run commands directly:
```bash
nix develop -c [command]
```

You don't need `nix develop` to call nix subcommands (`nix flake check`,
`nix build`, etc.) — only for cargo.

## Testing

### Rust tests
```bash
cargo test --workspace
```

Sign-only sanity (drops the `verify` feature in `laut-cli`, but still tests
the whole workspace since cargo doesn't drop workspace members):
```bash
cargo test --workspace --no-default-features
```

The verification orchestrator's integration tests live in
`laut-verify/tests/orchestrator_fixtures.rs` and `…/debug_probe.rs`; they
read fixtures from `<repo>/tests/data/` and keys from `<repo>/testkeys/`.

### Nix builds
```bash
nix build .#laut .#laut-sign-only
```

### NixOS VM tests
End-to-end integration tests (signer + verifier VMs). Tests come in
`{small,medium,large} × {ca,ia}` flavors; the IA flavors exist as red
baselines until IA support is wired up end-to-end.
```bash
nix build .#checks.x86_64-linux.small-ca-sign
nix build .#checks.x86_64-linux.small-ca-verify
nix build .#checks.x86_64-linux.small-ia-sign
nix build .#checks.x86_64-linux.small-ia-verify
nix build .#checks.x86_64-linux.debug-probe
```

The `debug-probe` test exercises `laut verify --debug-preimage-corpus` by
tampering one trace's signed preimage and asserting the structural diff
surfaces the marker. CA-only.

Run interactively:
```bash
nix build .#checks.x86_64-linux.small-ca-sign.driverInteractive
./result/bin/nixos-test-driver
# then: test_script()
```

### Rebuild isolation
Editing a file under `laut-verify/` must not change the
`.#laut-sign-only` derivation hash. To verify:
```bash
P=$(nix path-info .#laut-sign-only)
touch laut-verify/src/lib.rs
[ "$P" = "$(nix path-info .#laut-sign-only)" ]
```

## Key commands

### Signing (called from a post-build hook)
```bash
laut sign-and-upload --to [HTTP_CACHE_URL] --secret-key-file [KEY] [DRV_PATH]
```

`$OUT_PATHS` (set by `nix` in the post-build hook) supplies the output paths.
Exit codes: `0` = signed, `117` = no-op (the hook fired on the unresolved
drv or on a FOD/IA), `1` = error.

### Verification
```bash
laut verify --cache [URL] --trusted-key [KEY.public] [DRV_PATH_OR_FLAKE_REF]
```

A target is detected as either `/nix/store/*.drv` or a flake reference
(`pkg#attr`); flake refs are resolved via `nix eval --raw <ref>.drvPath`.
Multiple `--cache` and `--trusted-key` flags are allowed.

Exit codes: `0` = verified, `118` = verification failed, `1` = error.

### Hash-divergence debug probe
```bash
laut verify --cache [URL] --trusted-key [KEY] \
  --debug-preimage-corpus [URL] \
  --debug-out-dir [DIR] \
  [TARGET]
```

When a `ct_input_hash` lookup misses, the probe scans the corpus URL for
signer-side debug preimages with a matching `drv_name` and renders a
`difft` structural diff between the local and the signer's preimage. The
corpus URL accepts `http(s)://` (requires the cache to expose
`GET /traces/`, which most production caches refuse) or `file://`.

## Architecture notes

- **Sign-side orchestration**: `laut-sign/src/sign.rs` is the entry; the JWS
  payload assembly is in `sign/jws.rs`, the `$NIX_CONFIG` regex in
  `sign/nix_version.rs`.
- **Verify-side orchestration**: `laut-verify/src/orchestrator.rs` is the
  entry. Sub-modules under `orchestrator/`:
  - `tree.rs` — DFS that builds `UnresolvedDerivation` nodes.
  - `resolutions.rs` — cartesian product over deps' plausible resolutions,
    feeds the verifier's facts.
  - `compute.rs` — resolved-input-hash computation + signature fetch/verify.
  - `report.rs` — success/failure formatting + candidate-output-map collection.
- **Trust models**: Rust types in `laut-verify/src/verifier.rs`
  (`TrustModel::Key(KeyId)` and `TrustModel::Threshold(n, Vec<TrustModel>)`).
  Evaluated by the two-pass `Verifier` in the same file (see `docs/semantics.md`
  for the formal definition).
- **Storage**: HTTP cache with a `traces/<input-hash>` path layout, accessed
  via `ureq`. The `Backend` trait in `laut-verify/src/backend.rs` abstracts
  cache I/O so tests can use an in-memory backend.
- **Snix integration**: ed25519 keyfile parsing, ATerm derivation handling,
  and castore entry encoding come from `nix-compat` / `laut-compat` on the
  `mschwaig/snix#fanfic` branch. The branch hash is pinned in
  `nix/laut.nix` (`snix-hash`) and `Cargo.lock` (`source` field).

## Development guidelines

1. **No parallel code paths.** Create a single, robust implementation rather
   than multiple fallback paths. Debug to find the root cause; don't add
   fallback shims that create redundant ways to do the same thing.
2. **Trust internal callers.** Only validate at system boundaries (CLI args,
   external APIs, HTTP responses). Don't add `Option` plumbing for fields
   that can't be absent in practice.
3. **Tests.** Unit tests live next to the code (`#[cfg(test)] mod tests`).
   Integration tests that touch fixtures or end-to-end flows go in
   `<crate>/tests/`. End-to-end binary behavior is covered by the NixOS VM
   tests under `vm-tests/`.
4. **New files for the Nix source filter.** When adding a new file under a
   Rust crate, `git add -N` it so the Nix `fileset` (which works off the
   git index) picks it up. Forgetting this makes `nix build` complain that
   the file is missing.

## Common tasks

### Adding a new field to the signed JWS payload
1. Build the field into the payload object in `laut-sign/src/sign/jws.rs`
   (the `payload = json!({ ... })` block).
2. If the field surfaces to the verifier, parse it in
   `laut-verify/src/orchestrator/resolutions.rs` (the `for (payload, kid)`
   loop) and feed it into the verifier facts via `add_*_to_facts`.
3. Add a unit test in `sign/jws.rs` asserting the field round-trips.
4. If the field shape affects VM-test behavior, refresh the relevant test
   under `vm-tests/`.

### Debugging hash mismatches
Use the `--debug-preimage-corpus` flag against a cache that carries
signer-side preimages (signers must have been run with `--include-preimage`).
The probe writes the local and signer preimages to `--debug-out-dir` and
prints a `difft` structural diff to stderr. For unit-level inspection of
the orchestrator's resolution combinatorics, run
`cargo test --workspace -- --nocapture` and the eprintln traces show up.

### Bumping snix
1. Push the new commit to `mschwaig/snix` (branch `fanfic`).
2. Update `rev` in `nix/laut.nix` to the new hash.
3. Run `cargo update -p laut-compat` to refresh the `source =` line in
   `Cargo.lock` to the new rev.
4. `nix build .#laut .#laut-sign-only` will fail with a hash mismatch — first
   on the snix `fetchgit` (`snix-hash`) since the tree changed, and then on
   the cargo `laut-compat-0.1.0` `outputHashes` entry (which reuses
   `snix-hash`). Copy the `got:` hash into `snix-hash` and rebuild; the
   cargo entry inherits it.

## File structure

```
Cargo.toml         workspace manifest
Cargo.lock
laut-cli/          binary "laut": clap CLI + dispatch
laut-sign/         sign-side orchestration + shared core
laut-verify/       verify-side orchestration + trust-model evaluator
nix/laut.nix       Rust binary derivation (sign-only via fileset + postPatch)
flake.nix          flake outputs (packages.{laut,laut-sign-only}, checks, devShell)
default.nix        scope wrapper for callPackage convenience
testkeys/          ed25519 keypairs used by Rust + VM tests
tests/data/        Rust integration test fixtures (drv JSONs, signatures, ATerms)
vm-tests/          NixOS VM tests (small-sign, small-verify, debug-probe)
docs/semantics.md  formal trust-model semantics
```
