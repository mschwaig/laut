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

The report tool pairs the rooted recipe graphs and, by default, compares
**recorded Nix metadata**, without hashing contents or authenticating signatures.
It reports dependency-first and stops attributing new local divergences above a
failing dependency. Same-name ambiguities remain explicit failures.

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
  status unless both caches are supplied, rather than comparing an ordinary IA
  NAR with rewritten CA content.

Copied runs sharing a run ID and self-comparisons are rejected. Distinct run IDs
do not themselves prove that builders were independent. Without cache arguments,
normalized input hashes and synthetic CA identities remain untested.

### Signed-Claim Diagnostics

Supply both cache roots to additionally compare the existing signed claims.
This supports IA/CA, repeat, and baseline-to-seed comparisons:

```sh
nix develop -c python3 -B vm-tests/compare-experiments.py \
  --left result-ia/experiment/builderA/laut-experiment \
  --right result-ca/experiment/builderA/laut-experiment \
  --left-cache result-ia/cache --right-cache result-ca/cache \
  --output /tmp/opencode/laut-signed-ia-ca
```

The selected builder's public-key fingerprint and bundle hint filter the shared
cache. Realized outputs join inventory nodes to hook observations, and the debug
`rdrv_path` joins those hooks to bundles, including CA's resolved hook derivations.
Missing or ambiguous bundles/hooks fail; names alone never select a signature.
Reports retain the bundle path, line, SHA-256 of that exact JSONL line, signed
invocation, hook IDs, and actual named outputs. Hook UUIDs are distinct from signed
invocation IDs. The current helper requires hooks and subjects to cover exactly
the requested outputs; extra unrequested outputs are rejected, not guessed.

For each non-FOD pair, the report compares the signed resolved-input `aterm`
identity and exact normalized ATerm bytes independently, then compares each
named output's `nix-ca-store-path`, `nix-nar-sha256`, and decoded
`snix-castore-entry` bytes. It never substitutes Nix's recorded unseeded metadata
for these identities. FODs remain explicit metadata-only boundaries. Ordinary
IA and CA NAR metadata is not compared across modes.

Exact preimages are saved under `preimages/<pair-sha256>/{left,right}.aterm`.
Differing preimages also get `structural.diff` and `difft.stderr`, using the same
Python grammar override as the verification debug probe. Byte differences still
fail even if the structural diff reports none. Available preimages survive a
missing counterpart. Blocked dependents retain diagnostics but cannot extend the
dependency-closed agreement frontier. Run inside `nix develop` to provide `difft`;
a failed/missing diff tool is recorded as an error.

Exit zero with caches means **diagnostic agreement of extracted claims**, not
authentication or full equivalence. Signatures, source contents, correspondence
between a claimed input hash and its preimage, and output contents are not
verified/recomputed. Synthetic NAR sizes are not present in the signed identities.
These limitations remain explicit in JSON; no diagnostic result feeds trust facts
or relaxes the mixed-addressing restriction.

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
returned `unsupported` (exit 2), not agreement, before synthetic identity extraction
was implemented. The demonstrated synthetic/native equivalence frontier was still
empty; this baseline provides reproducibility/reference-transparency evidence
for the tested perturbations, not answers to the remaining hashing questions.

These store paths identify local observations, not permanently hosted artifacts.
Keep result links or another GC root for runs that remain under investigation.

### Signed Identity Ledger

2026-09-20, comparison support `dde55e9`, `41b344b`, and `1b597c3`, using the
same immutable four-configuration artifacts above. No workloads were rebuilt;
these are new analyses of the existing observations, not additional repeats.
No VM tests, bootstrap patches, dependency bumps, or host-daemon changes were
needed. The mixed-addressing restriction and trust admission are unchanged.

All eight reports have six paired nodes, no correspondence/collection/schema
errors, and successful structural-diff commands where needed:

| Comparison | Result | Exit |
| --- | --- | --- |
| IA, seed A, seed B, CA: builder A versus B, four reports | All four rebuilt nodes agree on signed input/output claims and exact ATerms; two FOD boundaries agree on metadata | 0 |
| IA versus seed A, builder A | `bootstrap-tools` divergent; three dependents blocked; two FOD boundaries agree | 1 |
| IA versus seed B, builder A | Same | 1 |
| IA versus CA, builder A | Same | 1 |
| IA versus CA, builder B | Same | 1 |

Reports live under `/tmp/opencode/laut-signed-{ia,seed-a,seed-b,ca}-repeat/`,
`/tmp/opencode/laut-signed-cross-seed-{a,b}/`,
`/tmp/opencode/laut-signed-ia-ca/`, and
`/tmp/opencode/laut-signed-ia-ca-builder-b/`. Reproduce with the cache-enabled
command above, substituting the table's immutable outputs and builder names.
All four rebuilt nodes have differing input/output claims in each failed report;
only the earliest, `bootstrap-tools`, is attributed locally. Its three blocked
dependents are `bootstrap-stage0-stdenv-linux`,
`bootstrap-stage0-glibc-bootstrapFiles`, and
`bootstrap-stage0-binutils-wrapper-`.

The dependency-closed synthetic/native agreement frontier remains empty beyond
the two metadata-only FOD boundaries. Signature authentication, full source
comparison, and synthetic NAR size comparison remain untested.

#### Recipe Difference

At `bootstrap-tools`, IA's normalized input identity is
`2lz7xkklxh2dxcs9s43bmmdz9cmdw9v8`; CA's is
`jy80sl8j6218d6mwnqlyirmhskxibags`. The exact ATerms differ only in two native-CA
environment entries: `outputHashAlgo=sha256` and `outputHashMode=recursive`.
Sources, resolved FOD paths, builder executable, arguments, and own-output
placeholder agree at this node.

This is a real recipe difference, not an ATerm parser omission. At the pinned
nixpkgs revision, `pkgs/stdenv/linux/bootstrap-tools/default.nix:17-25` adds these
attributes only under `config.contentAddressedByDefault`; `glibc.nix` passes them
to `derivation`. Nix retains the explicit attributes in the builder environment,
but can also create recursive SHA-256 floating outputs using defaults **without**
these environment fields (`src/libexpr/primops.cc` at the pinned Nix revision).
Inserting or dropping them during hashing would identify distinguishable recipes.
The new `ia_normalization_preserves_explicit_hash_environment` Rust regression
checks absent fields and explicit `recursive`/`nar` values against corresponding
native-shaped ATerms, without changing the production normalization.

#### Self-Reference Hashing

The output mismatch is independently localized to self-reference addressing:

| Layer | Observed Value |
| --- | --- |
| Original IA path hash | `razasrvdg7ckplfmvdxv4ia3wbayr94s` |
| Signed synthetic path hash | `akqphqb3rn9zvv8dbnsw9rmi2899w7f0` |
| Native CA path hash | `n7cxavpfzzz2pb1a71fg5hy1mqf1xlf2` |
| Both NAR sizes | `140352008` bytes |
| Self-hash occurrences in each NAR | `111` |
| Zero-masked NAR SHA-256, Nix base32 | `0asyng1f449h2bk3dcdwkxyzips956npk2nchm7m83kqqk849ls4` |
| Zero-masked NAR plus `\|position` suffixes, SHA-256, Nix base32 | `1jbircp9pzxnfjvna7avpiyrjganpxhw84x4qid5jln40lx1lcsy` |

Replacing just the original IA self hash with the native CA self hash makes the
complete serialized NARs **byte-for-byte equal**. The zero-masked hash equals the
native cache's declared CA hash. Rewriting to laut's signed synthetic self hash
instead yields SHA-256
`68e1832473500f23f25d0cdadb8aa65b469d4b2487a326507538d96a3511ba71`, exactly the
signed synthetic NAR identity. Native CA's final NAR identity is
`397dae7c565275036841c3e55e2193da0f59f64b8f131edd849850a3440810f0`.
This is a targeted content comparison for this one output, not whole-closure or
cross-seed content equivalence; castore roots were not independently recomputed.

At pinned Nix `40ab933003b7f0bc9fd9270fd95aca2d2dc34c24`,
`src/libstore/references.cc:76-102` rewrites bytes without populating `matches`.
`HashModuloSink::finish()` still loops over that empty vector at lines 119-124,
so no self-reference position suffixes reach the hash. The native build path
uses this sink in `src/libstore/unix/build/derivation-builder.cc:1366-1370`.
In contrast, pinned Snix `95cd1ba7515d409edaf0dfb249f6cdf327f4c209`,
`snix/laut-compat/src/content_hash.rs:348-370`, records and hashes the positions.
The latter prevents already-zeroed content from colliding with masked references;
do not remove that protection merely to match this experimental Nix revision.

The local one-off diagnostic is `/tmp/opencode/laut-bootstrap-nar-diagnostic.py`.
The essential byte-level check can be reproduced independently as follows; `IA`
and `CA` below are `pathlib.Path` values for the immutable test-output directories
in the baseline table:

```python
import hashlib
import lzma

contents = "experiment/builderA/laut-experiment/builderA/contents/nar"
left = lzma.decompress((IA / contents /
    "1hm5gxjc66q8z5c2l1xqhj6103san9k0cp2fgdzvfp1f96bjqv5x.nar.xz").read_bytes())
right = lzma.decompress((CA / contents /
    "0ghv4ji22hrwzy80kjvpjfkjsc449545lf90nhc01hk3lgqv5q97.nar.xz").read_bytes())
ia_self = b"razasrvdg7ckplfmvdxv4ia3wbayr94s"
ca_self = b"n7cxavpfzzz2pb1a71fg5hy1mqf1xlf2"
assert len(left) == len(right) == 140352008
assert left.count(ia_self) == right.count(ca_self) == 111
assert left.replace(ia_self, ca_self) == right
masked = left.replace(ia_self, bytes(32))
assert masked == right.replace(ca_self, bytes(32))
assert hashlib.sha256(masked).hexdigest() == (
    "44d344d0c4780e544f85cc8a79ad2949dff87d9fbcb136e6123011e2c2b35e2b")
```

#### Seed Boundaries

Both baseline-to-seed comparisons differ first in the retained FOD paths for
`busybox` and `bootstrap-tools.tar.xz`, and the source path for
`unpack-bootstrap-tools.sh`. These appear in the normalized input-source list,
builder, arguments, and environment. The signed output identities also differ.
Stable repeats and matching recorded-unseeded metadata do not resolve these
synthetic-namespace questions. No source/FOD remapping or new scanner behavior
was introduced.

#### Validation

- `nix build .#checks.x86_64-linux.experiment-tools --no-link --print-out-paths`:
  113 offline tests and lint pass; output
  `/nix/store/726anmfn278wwrdsvc6dp2aq9xc67wz6-laut-experiment-tools-tests`.
- `nix develop -c cargo test --workspace`: 95 Rust tests pass.
- `nix develop -c cargo test --workspace --no-default-features`: 95 pass.
- Eight retained small-graph comparisons rerun after association/schema review;
  outcomes unchanged, with all 16 required structural diffs successful.

## Remaining Work

- Reproduce and correct the pinned Nix self-reference position regression in a
  tiny native-CA oracle before selecting a revised experimental Nix pin. Preserve
  the old observations; do not add a laut hash-version fallback.
- Establish common builder-visible recipe attributes for an additional controlled
  IA/CA experiment, with a reviewable common-source patch rather than silently
  inserting or removing environment fields in normalized ATerms.
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

## Tiny Native CA Oracle

`small-ca-oracle` builds seven tiny native CA outputs in one isolated 2 GiB VM:
plain content, one/two self hashes, a partially zeroed self hash, a large streaming
file, a self-referencing symlink, and an external native-CA dependency. No IA
builds or mixed-addressing dependency graphs are used. The Rust diagnostic example
`ca_identity_probe` calls the existing compatibility pass-1/pass-2 functions on
each native output, checking idempotence of its path, final NAR hash/size, and
castore entry. Python independently checks only the zero-masked NAR plus position
suffix preimage against Nix's recorded CA hash; it does not derive synthetic paths.

```sh
nix develop -c cargo test -p laut-sign --example ca_identity_probe
nix build .#checks.x86_64-linux.experiment-tools --no-link
nix build .#checks.x86_64-linux.small-ca-oracle \
  --no-link --print-out-paths --keep-failed --max-jobs 1
```

The oracle requires agreement, not the known broken behavior. Its first run
against unpatched Nix `40ab933...` was intentionally red:
`/nix/store/crngy1ijf4l7jwbmizblbwdy0kkxrlx7-vm-test-run-laut-small-ca-oracle.drv`.
All seven outputs built and collected with zero errors. Plain and external-ref
controls agree; all five self-reference cases fail the CA hash, synthetic path,
rewritten NAR hash, and castore comparisons. NAR sizes and reference counts agree.

The two-self and zero-plus-self cases both have 184-byte NARs and the same masked
SHA-256 `93d3d3b1c296bf27833c0c50447616bff6317148ef2d1481d9fbd4b0d4a4c550`,
but self positions `[96, 130]` versus `[130]`. The unpatched Nix assigns the same
CA content hash to both, demonstrating the missing position discrimination without
the bootstrap closure. Their store names deliberately differ to avoid output-path
collisions in the VM. This is a CA-content-hash collision, not a SHA-256 collision.

The full baseline report is embedded in
`/tmp/opencode/laut-ca-oracle-unpatched.log` (also available via `nix log` of the
derivation above). Failed VM disks remain under
`/nix/var/nix/builds/nix-367851-118118654/build`; failed checks do not produce valid
store outputs. Successful runs export `ca-oracle/report.json`, exact NARs, original
ATerms, probe results, and command/stdout/stderr sidecars. The example's three
tests and all 116 offline experiment tests pass at this baseline.
