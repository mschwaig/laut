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

## Compare Observations

The initial report tool pairs the rooted recipe graphs and compares **recorded
Nix metadata**, without hashing contents or authenticating signatures. It reports
dependency-first and stops attributing new local divergences above a failing
dependency. Same-name ambiguities remain explicit failures.

```sh
python3 -B vm-tests/compare-experiments.py \
  --left result-ia/experiment/builderA/laut-experiment \
  --right result-ia/experiment/builderB/laut-experiment \
  --output /tmp/laut-ia-repeat

python3 -B vm-tests/compare-experiments.py \
  --left result-ia/experiment/builderA/laut-experiment \
  --right result-seed-a/experiment/builderA/laut-experiment \
  --output /tmp/laut-cross-seed
```

For repeat builds, it compares actual output paths, NAR hashes/sizes, and
registered references. For cross-seed checks, one side must be an empty-seed
baseline; the other side supplies Nix's recorded unseeded metadata. Preloaded
FODs use the exported boundary mappings. Compare both seeds separately against
the same baseline, rather than treating seed A as canonical for seed B.

The report is `report.json` in the output directory. Exit codes:

- `0`: the selected baseline metadata checks agree, not full equivalence.
- `1`: invalid configuration, missing/ambiguous evidence, or divergence.
- `2`: the comparison is unsupported. IA versus CA currently returns this
  status rather than comparing an ordinary IA NAR with rewritten CA content.

Copied runs sharing a run ID and self-comparisons are rejected. Distinct run IDs
do not themselves prove that builders were independent. Normalized input hashes,
source-content comparison, synthetic CA identities, and signature authentication
remain untested by this report; those limitations are also explicit in its JSON.

The existing verification probe (`--debug-preimage-corpus` with
`--debug-out-dir`) now retains the local ATerm even when its corpus has no
same-name candidate, and prints the saved path. This does not change signature
admission or the probe's failure-triggered activation.

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
- The report tool adds 33 offline tests for pairing, blocked dependents, missing
  metadata, invalid experiment controls, self-comparison, and unsupported IA/CA
  comparisons. `experiment-tools` now runs all 71 tests.
- The debug-probe integration suite passes all 11 tests, including the corrected
  no-candidate artifact assertion. The verification-only change leaves the
  sign-only derivation unchanged.
- Each initial configuration's builder-A/builder-B repeat report agrees at all
  six nodes. Unseeded IA versus seed A also agrees at all six nodes using Nix's
  unseeded metadata and the FOD boundary mappings. Four nodes are fresh build
  observations; two are preloaded inputs. This establishes no synthetic/native
  CA equivalence yet.

### Final Baseline

The complete four-configuration matrix passed after the hook-failure diagnostic
improvements (`be856a7` harness, `09e54fb` report tool). Both laut packages also
built successfully with the `e930df0` debug-probe change. No medium/large VM tests
or bootstrap patches were used.

```sh
nix build .#checks.x86_64-linux.small-equivalence-ia-sign \
  .#checks.x86_64-linux.small-equivalence-ia-seed-a-sign \
  .#checks.x86_64-linux.small-equivalence-ia-seed-b-sign \
  .#checks.x86_64-linux.small-equivalence-ca-sign \
  --max-jobs 1 --no-link --print-out-paths --keep-failed
nix build .#laut .#laut-sign-only --no-link --print-out-paths
```

| Configuration | Immutable Test Output |
| --- | --- |
| IA | `/nix/store/pgman8abavacbcq68iip55mjg78d20j1-vm-test-run-laut-small-equivalence-ia-sign` |
| IA seed A | `/nix/store/0849amf0yyr3lz3353i7nzcxw0vnkyd8-vm-test-run-laut-small-equivalence-ia-seed-a-sign` |
| IA seed B | `/nix/store/k2j7md25w9b3jmf308gnzj8jxddddc1g-vm-test-run-laut-small-equivalence-ia-seed-b-sign` |
| CA | `/nix/store/nx1qvx02n9ks9ivms794lxf6989z30vp-vm-test-run-laut-small-equivalence-ca-sign` |

All four within-configuration A/B comparisons and both IA-to-seed comparisons
reported six paired nodes, zero collection/schema errors, and agreement of the
selected metadata. Cross-seed comparisons used builder A of each configuration;
the within-configuration reports separately compared both builders.

| Node | Evidence |
| --- | --- |
| `busybox` | Preloaded FOD boundary; canonical/seeded mapping agrees |
| `bootstrap-tools.tar.xz` | Preloaded FOD boundary; canonical/seeded mapping agrees |
| `bootstrap-tools` | Rebuilt; repeat and recorded-unseeded metadata agree |
| `bootstrap-stage0-stdenv-linux` | Rebuilt; repeat and recorded-unseeded metadata agree |
| `bootstrap-stage0-glibc-bootstrapFiles` | Rebuilt; repeat and recorded-unseeded metadata agree |
| `bootstrap-stage0-binutils-wrapper-` | Rebuilt; repeat and recorded-unseeded metadata agree |

Local JSON reports are under `/tmp/opencode/laut-final-{ia,seed-a,seed-b,ca}-repeat/`
and `/tmp/opencode/laut-final-cross-seed-{a,b}/`. They can be regenerated from
the table's artifacts using the commands above. The IA/CA report correctly
returns `unsupported` (exit 2), not agreement, until synthetic identity extraction
is implemented. The demonstrated synthetic/native equivalence frontier is still
empty; this baseline provides reproducibility/reference-transparency evidence
for the tested perturbations, not answers to the remaining hashing questions.

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
