# IA / CA Experiment Runbook

This records implementation progress for the
[equivalence investigation](ia-ca-equivalence-plan.md). Artifact formats are
development interfaces, without backward-compatibility guarantees.

## Build and Collect

Each variant is a separate signing-side VM test, with two independent builders
using the same configuration. Consumers use their outputs separately; no cache
composition is needed. Only the existing small bootstrap target is used.

```sh
nix build .#nix-seeded --no-link
nix build .#checks.x86_64-linux.experiment-tools --no-link
nix build .#checks.x86_64-linux.small-equivalence-ia-sign --keep-failed -o result-ia
nix build .#checks.x86_64-linux.small-equivalence-ia-seed-a-sign --keep-failed -o result-seed-a
nix build .#checks.x86_64-linux.small-equivalence-ia-seed-b-sign --keep-failed -o result-seed-b
nix build .#checks.x86_64-linux.small-equivalence-ca-sign --keep-failed -o result-ca
```

Run VM tests sequentially locally to bound memory use. Reusing a completed test
output reuses its observations, not a new independent build. The two builders
inside a test disable workload substitution and retain separate contents caches.

All four configurations use Nix revision
`40ab933003b7f0bc9fd9270fd95aca2d2dc34c24`, including the empty-seed baselines.
Its package uses its own locked nixpkgs input: laut's infrastructure pin has
libcurl 8.14.1, below this Nix revision's 8.17.0 minimum. Neither laut's existing
infrastructure pin nor the package-under-test pin was updated.

Prefetched FODs are re-added inside the VM with their declared flat/NAR method,
hash algorithm, and store name. Their canonical paths and NAR identities are
checked and their seeded mappings exported. NixOS's initial store registration
does not retain their CA metadata, so the preparation manifest carries the
declared addressing information explicitly. These inputs are not counted as
rebuilt outputs. The host daemon and sibling checkouts are not modified.

## Artifacts

Each test output contains:

```text
cache/                                    uploaded bundles and binary cache
experiment/builderA/laut-experiment/       builder A's observation directory
experiment/builderB/laut-experiment/       builder B's observation directory
```

Within each observation directory:

- `manifest.json`: configuration, immutable package/source paths, revisions,
  root derivation, public key, schema version, and unique run ID.
- `derivations.json`, `aterms/`, `inventory.json`: recursive recipe inventory
  and exact original ATerms, including build-time-only dependencies.
- `prebuild-path-info.json`: validity snapshot before the workload build.
- `seeded-inputs.json`: canonical-to-seeded correspondence for preloaded FODs.
- `observations/<uuid>/`: hook derivation, ATerm, output metadata, signing exit
  status, and collection errors for each invocation. Exit zero can mean a signing
  no-op; it is not interpreted as a signature or verification result.
- `paths.json`, `realized-path-info.json`, `collect.json`: realized named outputs,
  sources, registered references, provenance of observations, and completeness.
- `<hostname>/contents/`: this builder's independent file binary cache. The
  `contents_cache` URI in `collect.json` records the original in-VM destination;
  use the exported relative directory when consuming it outside the VM.
- Command sidecars preserve stdout, exit status, and stderr. Private key files
  are not exported.

On failure, builders attempt partial collection and the driver exports the cache
before raising the error. `--keep-failed` retains those diagnostics in Nix's
failed build directory; a failed build does not produce a valid test output.
Missing evidence remains an error, not empty-equals-empty agreement.

## Initial Ledger

2026-09-20, x86_64-linux, nixpkgs under test
`979daf34c8cacebcd917d540070b52a3c2b9b16e`, Snix compatibility revision
`95cd1ba7515d409edaf0dfb249f6cdf327f4c209`, no bootstrap patches:

- `ededea9`: derivation summaries now use one stored-ATerm reader, not a
  version-dependent Nix JSON adapter. Workspace tests pass with and without
  default features (94 tests in each configuration).
- The pinned experimental Nix package built successfully. An attempted build
  against laut's infrastructure nixpkgs failed at the libcurl version check;
  keeping Nix's own dependency set resolved that packaging issue.
- Initial IA, CA, and seed-A signing tests completed on both builders, with
  complete per-builder exports. The small graph has six derivations: four
  rebuilt outputs and two preloaded FOD boundaries. Each IA builder collected
  33 realized paths, including build-time-only inputs and source files.
- The collector/preparation check passes 38 offline tests, including missing
  observations, unresolved CA outputs, separate hook invocations, flat versus
  NAR FOD preparation, and lost initial CA metadata.

Initial captured test outputs, before subsequent hook-failure diagnostic
improvements:

| Configuration | Immutable Test Output |
| --- | --- |
| IA | `/nix/store/9y6ab5i7hi6siibdyy3lmcnp3yqvg4dr-vm-test-run-laut-small-equivalence-ia-sign` |
| IA seed A | `/nix/store/78cmzzgdy4cdcwrb6s2ipfbxqxzv26pi-vm-test-run-laut-small-equivalence-ia-seed-a-sign` |
| CA | `/nix/store/s2gmii9j6qw4jpw6xb9hhy4m03k90r30-vm-test-run-laut-small-equivalence-ca-sign` |

These store paths identify local observations, not permanently hosted artifacts.
Keep result links or another GC root for runs that remain under investigation.

## Remaining Work

- Extract and compare the existing signed synthetic/native identities and exact
  normalized ATerms using the paired graph, with structural diff artifacts.
- Establish seed-independent synthetic source/FOD normalization. Nix's recorded
  unseeded NAR metadata is a different normalization and must not substitute for
  laut's synthetic identities.
- Handle preloaded FODs with non-leaf build recipes before extending the target:
  the current collector requires the recursively inventoried build dependencies
  to be available, even when a preloaded FOD makes its fetcher unnecessary. The
  small target's two FODs are leaves and do not exercise that limitation.
- Compare source contents separately from the output checks, and distinguish
  diagnostic extraction from signature authentication. No new trust admission
  rule or hashing-algorithm fix has been introduced by this harness.
