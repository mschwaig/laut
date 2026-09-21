# IA / CA Experiment Runbook

This records implementation progress for the
[equivalence investigation](ia-ca-equivalence-plan.md). Artifact formats are
development interfaces, without backward-compatibility guarantees.

## Build and Collect

Each variant is a separate signing-side VM test, with two independent builders
using the same configuration. Consumers use their outputs separately; no cache
composition is needed. The harness supports the existing small and medium
bootstrap targets and the large `hello` target. Start with small; medium and
large runs require agreement and should run sequentially.

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
Current definitions additionally apply the self-reference position correction
documented under **Tiny Native CA Oracle** below; the initial ledger's artifacts
remain unpatched. Manifests record the base revision, package path, and patch hash.
The current experiment package source also disables linker build IDs as described
under **Build-ID Suppression Experiment** below. Earlier immutable results retain
their original, unpatched package source.
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
invocation IDs. Multi-output hooks must cover the complete recorded output-name
and path mapping before their claims are projected onto requested outputs.
CA candidates must also have the original recipe's sources plus its realized
dependency outputs as their resolved inputs. This distinguishes recipes that
produce identical outputs; it is not recipe authentication. Missing linkage,
repeated matching hooks, and duplicate matching bundles remain errors.

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
  diagnostic extraction from signature authentication. Exercise hashing fixes
  through production signing and verification without changing trust admission.
- Investigate producer-scoped normalization when an opaque source's producer is
  known only through an unrelated sibling branch. The current graph-wide candidate
  universe can differ between signing a child and verifying a larger root; the
  ordinary-output/source overlap test does not cover that graph-context question.

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

### Position Correction

The correction is a reviewable local backport on the unchanged remote base pin,
not an undocumented sibling-checkout change. `nix/rewriting-sink-positions.patch`
backports the focused production changes from the locally available Nix commits
`f546f4b8356ccceb21e2aff355daae1b7a7b3ee7` and
`7523932a1d23c35395cf241703f30b7e19604add`, with deterministic C++ regressions.
The originating regression is `3ebe1341abe1b0ad59bd4925517af18d9200f818`.
This records local history provenance, not a claim that the proposed fix is merged
upstream. Patch SHA-256:
`d58a056d75310eb219fbfc6f520c96ef1fbb25354174452409ff741f146fc9e3`.

Position tracking instruments the existing rewrite operation, records absolute
stream offsets, and keeps them sorted and unique. Tests cover every split and
chunk size of a noninteracting multikey fixture, repeated flushes, exact hash
suffixes, original byte counts, and partially zeroed references. General semantics
of interacting rewrite maps were not redesigned. No legacy-hash admission or
compatibility branch was introduced.

The flake uses the pinned Nix component scope's `appendPatches`, rebuilding the
CLI and libraries consistently with Nix's own dependency package set. Both the
oracle and all four experiment definitions use that package; experiment manifests
now include `nixPatches`. Changing only the CLI source would not fix its separately
built libraries. The host daemon and sibling checkout remain unchanged.

```sh
nix build .#nix-seeded .#checks.x86_64-linux.nix-seeded-store \
  .#checks.x86_64-linux.small-ca-oracle \
  --no-link --print-out-paths --keep-failed --max-jobs 1 --cores 2
```

The corrected package is
`/nix/store/qhnjjw1mndgv6jpifj57brfhnwx7k4v6-nix-2.35.0pre20260612_40ab933+1`.
All 730 Nix store tests pass (one pre-existing test remains disabled), including
the new regressions. Test output:
`/nix/store/a8npxlafpa742ryn4cd9k3inz9wjz2xw-nix-store-tests-run`.

All seven native-CA oracle cases pass every comparison after the correction, and
the two partially-zeroed fixtures now have different CA content hashes. The
two-self hash is `sha256-MBG8rhye+ylPap20hFJodVAer0vNOvN1cTMBZIjAGsE=`; the
zero-plus-self hash is `sha256-ZoHVu2A0SQ1I571oK0SHepT0N+J2OcNQLcwpjC44xgM=`.
The reviewed oracle extends its dependency control to two external native CA
references and checks reordered/duplicated probe arguments. The probe sorts and
deduplicates references to match Nix's set semantics. Final oracle output:
`/nix/store/8ssfiw10nj8xq04hm7kh2q6c7613ga34-vm-test-run-laut-small-ca-oracle`.
The earlier corrected seven-case run, before the two-reference extension, is
`/nix/store/pqlb8bsnfpjxr57f40bdd9plwi0xrasp-vm-test-run-laut-small-ca-oracle`.

`cargo test --workspace --all-targets` passes 98 tests, including the three probe
tests. The final offline experiment-tools output (116 tests plus lint) is
`/nix/store/jqzcv8bqw9gvwqvv69kb09b0v884sf07-laut-experiment-tools-tests`.
This establishes native/synthetic idempotence for the tiny fixtures, not signed
bootstrap equivalence, seeded normalization, or authenticated provenance.

### Corrected Small Matrix

At `0c66b21`, all four small signing configurations were rebuilt sequentially,
with two independent builders each. No medium/large VM tests were run, and no
bootstrap recipe patch was applied. The sole Nix source correction is the patch
above; the base Nix and nixpkgs revisions remain unchanged.

```sh
nix build .#checks.x86_64-linux.small-equivalence-ia-sign \
  .#checks.x86_64-linux.small-equivalence-ia-seed-a-sign \
  .#checks.x86_64-linux.small-equivalence-ia-seed-b-sign \
  .#checks.x86_64-linux.small-equivalence-ca-sign \
  --out-link /tmp/opencode/laut-position-fix-results \
  --print-out-paths --keep-failed --max-jobs 1
```

| Configuration | Immutable Test Output |
| --- | --- |
| IA | `/nix/store/n3l45bb23mh2jjw0hhrh1z2s1g3fw6il-vm-test-run-laut-small-equivalence-ia-sign` |
| IA seed A | `/nix/store/44p3p5v121cqw4y7fki8x0ajgck735ic-vm-test-run-laut-small-equivalence-ia-seed-a-sign` |
| IA seed B | `/nix/store/w7yblrczbhn7awiimvdzhv08qvn65702-vm-test-run-laut-small-equivalence-ia-seed-b-sign` |
| CA | `/nix/store/yjx0r1sb3qkfp2d1fmscmfg8h8rg54m9-vm-test-run-laut-small-equivalence-ca-sign` |

Result links under `/tmp/opencode/laut-position-fix-results*` retain this matrix.
Eight signed-claim reports and two metadata-only cross-seed reports were run
against these matching controls; none combined patched and unpatched artifacts.
All have six paired nodes, zero collection/schema/correspondence errors, and no
unpaired nodes. All 16 structural-diff invocations succeeded.

- All four within-configuration builder-A/B reports show diagnostic agreement
  of all rebuilt input/output claims and exact ATerms, plus FOD boundary metadata.
- Both metadata-only baseline-to-seed reports still agree at every node, including
  Nix's recorded-unseeded path, NAR hash/size, references, and FOD mappings.
- Both signed baseline-to-seed reports still diverge first at `bootstrap-tools`,
  with three dependents blocked. All four rebuilt nodes' signed output identities
  differ; the earliest ATerm retains seeded FOD/source addresses as before.
- Both IA/CA builder pairs still diverge first in the `bootstrap-tools` recipe's
  explicit CA hash-environment fields. Its signed output identities now agree.

The per-output IA/CA diagnostics are identical on builders A and B:

| Rebuilt Node | CA Store Path | Final NAR SHA-256 | Castore Entry | Dependency Status |
| --- | --- | --- | --- | --- |
| `bootstrap-tools` | Equal | Equal | Equal | Recipe divergent |
| `bootstrap-stage0-stdenv-linux` | Different | Equal | Equal | Blocked |
| `bootstrap-stage0-glibc-bootstrapFiles` | Equal | Equal | Equal | Blocked |
| `bootstrap-stage0-binutils-wrapper-` | Equal | Equal | Equal | Blocked |

Native `bootstrap-tools` now has the synthetic path
`/nix/store/akqphqb3rn9zvv8dbnsw9rmi2899w7f0-bootstrap-tools`, confirming the
position correction on the real workload. Exact input identities still differ
at all rebuilt nodes. Matching downstream output claims does not bypass the
recipe failure or extend the dependency-closed equivalence frontier.

The remaining stdenv path-only discrepancy is independently characterized using
the existing `nix_compat::store_path::build_ca_path`, not a second hash routine:

- Both final NAR digests are
  `sha256:1i0sksjsmwjiikfjy1bb14w6fbgchjgvykzmn6gwzc6khjhyac8w` (60,064 bytes),
  and neither output is self-referencing.
- Supplying only the resolved `bootstrap-tools` output reference yields laut's
  `ckbi3dpd7gr7fcs48wq2fvdwy7rnqv0k-bootstrap-stage0-stdenv-linux`.
- Adding the 14 source-script references recorded by native Nix yields exactly
  `yfkmixcmvq3lnijhjn3sfdbyiwz6dsp1-bootstrap-stage0-stdenv-linux`.
- `sign_ia_outputs` currently constructs scan candidates from recursive derivation
  **outputs**, omitting input sources. Consequently these references do not reach
  `Walker::compute_pass1` even though their unchanged bytes survive in the NAR.

The new Rust test
`bootstrap_stdenv_path_difference_is_explained_by_source_references` pins both
observed paths and the full reference list. It characterizes the omission; no
source-boundary normalization or scanner change has been made yet. The node
remains reported as blocked, not as a newly independent local failure.

Reports are `/tmp/opencode/laut-corrected-{ia,seed-a,seed-b,ca}-repeat/`,
`/tmp/opencode/laut-corrected-cross-seed-{a,b}/`,
`/tmp/opencode/laut-corrected-ia-ca/`,
`/tmp/opencode/laut-corrected-ia-ca-builder-b/`, and
`/tmp/opencode/laut-corrected-metadata-cross-seed-{a,b}/`.
Signature authentication and full source-content comparison remain untested.

After adding the source-reference characterization, both
`nix develop -c cargo test --workspace --all-targets` and
`nix develop -c cargo test --workspace --all-targets --no-default-features`
pass 99 tests. That final Rust change is test/comment-only; the signing matrix
above remains explicitly identified by its build revision and immutable outputs.

## Source-Reference Fix

`dc47dd5` fixes the production IA-to-synthetic-CA computation, on both the signing
and verification sides. This is not just a diagnostic or an acceptance exception:

- The shared stored-ATerm reader now carries `inputSrcs` through `DrvJson` as a
  required field, including explicit empty lists. There is no missing-field default.
- `Walker::from_derivations` replaces the two output-only candidate-building loops.
  It includes declared input sources from the recursive derivation inventory.
- Sources without a known output producer and FODs retain their declared path
  identity instead of being readdressed as floating recursive-SHA256 outputs.
  Only actually scanned references enter the output's CA path computation;
  unused source candidates do not become references.
- A known ordinary output is still computed, even if an ancestor also mentions
  that path as an input source. The source declaration must not masquerade as
  independently computed output evidence in the verifier's memo.
- References are sorted and deduplicated **after** replacing IA output paths with
  their synthetic CA paths. Original IA-hash order need not be final CA-path order.

The shared walker has focused filesystem-backed pass-1 tests for discovered versus
unused sources, preserved flat FOD/source boundaries, and reordered references
after dependency substitution. Other tests cover ATerm source ingestion, ordinary
output/source overlap in both iteration orders, verifier setup, and unchanged
mixed IA/CA rejection with FOD exceptions. The original stdenv native-path fixture
remains as a regression oracle. No alternate legacy hash or signature admission
path was added.

### End-to-End Results

The new `small-equivalence-outputs` check consumes independently built small IA
and native CA signing artifacts. It uses the existing paired-graph comparator
for both builders and requires all three signed output identities to agree at
all four rebuilt nodes. Missing/ambiguous evidence, pairing failures, and output
divergences fail the check. Exact normalized-input differences and blocked-node
attribution remain in the exported reports; this check explicitly tests output
identity equality, not complete recipe equivalence or signature authentication.

```sh
nix build .#checks.x86_64-linux.small-equivalence-outputs \
  .#checks.x86_64-linux.small-ia-verify \
  .#checks.x86_64-linux.small-ca-verify \
  .#checks.x86_64-linux.experiment-tools \
  --out-link /tmp/opencode/laut-source-reference-fix \
  --print-out-paths --keep-failed --max-jobs 1 --cores 4
```

All checks passed. Only small VM tests were run, sequentially; the verification
checks also rebuilt their small signing prerequisites. The experiment pair uses
the corrected seeded-Nix package with empty seed, unchanged pinned nixpkgs, and
no recipe patch. The ordinary small verify checks use their existing test Nix
configuration and authenticate each mode's own signatures.

| Artifact | Immutable Output |
| --- | --- |
| Experimental IA sign | `/nix/store/cqiy0ljrwkv6llg7sg72wx2cl43kvygz-vm-test-run-laut-small-equivalence-ia-sign` |
| Experimental CA sign | `/nix/store/wq52yxiqr4f0r25n68xsm7farsx4bdkr-vm-test-run-laut-small-equivalence-ca-sign` |
| Output-identity comparison | `/nix/store/xz6d9plgdm2qhizhbvnna48kbkhqns2p-laut-small-equivalence-outputs` |
| Small IA verification | `/nix/store/ghyhxd6xcxsa6yyhyfdza6k6bglh7j0r-vm-test-run-laut-small-ia-verify` |
| Small CA verification | `/nix/store/yhibggypp9inj7dnkfwdrs174122s1wd-vm-test-run-laut-small-ca-verify` |

At **all four rebuilt nodes on both builders**, synthetic IA and native CA now
agree on `nix-ca-store-path`, `nix-nar-sha256`, and `snix-castore-entry`. In
particular, stdenv's synthetic path is now the native path
`/nix/store/yfkmixcmvq3lnijhjn3sfdbyiwz6dsp1-bootstrap-stage0-stdenv-linux`,
not the source-omitting `ckbi...` path. This closes the observed output identity
discrepancy; the change is reflected in production signatures and verification.

Both IA and CA builder-A/B repeat reports also agree at all six nodes, with no
collection/schema/correspondence errors. These reports are under
`/tmp/opencode/laut-source-fixed-{ia,ca}-repeat/`. Cross-mode reports and eight
successful structural diffs are in the comparison output's `builderA/` and
`builderB/` directories. At every rebuilt node, the **only** remaining exact ATerm
differences are CA's explicit `outputHashAlgo=sha256` and
`outputHashMode=recursive` environment entries. No dependency/source/path
differences remain in these normalized ATerms.

The full comparator therefore still reports one recipe-divergent node and three
blocked dependents, plus two metadata-only FOD boundaries. That is not an output
failure and is not silently relabeled full equivalence. Seed-independent source/FOD
normalization remains separate; seeded variants were not rerun in this fix slice.

Validation at `dc47dd5`: 105 Rust tests pass under both
`nix develop -c cargo test --workspace --all-targets` and
`nix develop -c cargo test --workspace --all-targets --no-default-features`.
The 116-test offline experiment check plus lint passes unchanged. Both full and
sign-only laut packages built as prerequisites of the VM checks.

## Medium And Large Expansion

2026-09-21, authorized medium-then-large expansion from `885cde2`, with the
uncommitted harness changes described here. Production hashing remains at
`dc47dd5`; no Rust, compatibility-library, Nix, or nixpkgs changes were made.
Both sizes use the same pins and self-reference-position patch as the corrected
small baseline, empty store-path seed, x86_64-linux, two independent builders,
and disabled workload substitution. Each builder has four vCPUs and 6 GiB RAM.
VM tests ran sequentially with `--max-jobs 1 --cores 4`.

### Harness Changes

- `makeEquivalenceSign` now exposes all four configurations for each size.
  Only unseeded IA and CA were run in this expansion; seed A/B remain untested.
- Required collection and pairing stop at FOD boundaries. Full recursive JSON
  and ATerms remain available, but fetcher-only recipe dependencies need not be
  built. Reports explicitly list excluded recipe derivations. Dependencies also
  reached through ordinary branches still require evidence.
- Multi-output bundle joining validates complete observed output mappings before
  selecting requested outputs. Resolved input-source sets distinguish CA recipes
  sharing output paths, without choosing by name or deduplicating observations.
- The output-equality checks cover both builders and both within-mode repeats.
  They pin inventories to 6/154/250 nodes and 4/77/157 ordinary nodes for
  small/medium/large. Known output divergences are not accepted as a baseline.

The first medium CA attempt was interrupted by the caller's one-hour timeout
while still building. The restarted run completed with the driver's existing
eight-hour allowance. An initial comparison-wrapper indentation error was fixed
without rebuilding the completed workloads. Early report failures from
multi-output coverage and shared CA outputs were resolved by replaying those
same artifacts, not by accepting missing evidence.

The final narrow collector regression fix prevents observations belonging only
to excluded FOD recipes from promoting those recipe inputs back into required
evidence. It was added after the medium/large builds; those outputs retain their
original collector. Their complete exported evidence passes the final comparator.
The final collector was exercised by fresh small IA and CA VM runs.

### Commands And Artifacts

For new runs, build medium first, inspect the reports, then build large:

```sh
nix build .#checks.x86_64-linux.medium-equivalence-ia-sign \
  .#checks.x86_64-linux.medium-equivalence-ca-sign \
  --out-link /tmp/opencode/laut-medium-sign \
  --keep-failed --max-jobs 1 --cores 4 --print-out-paths
nix build .#checks.x86_64-linux.large-equivalence-ia-sign \
  .#checks.x86_64-linux.large-equivalence-ca-sign \
  --out-link /tmp/opencode/laut-large-sign \
  --keep-failed --max-jobs 1 --cores 4 --print-out-paths
```

The medium signing outputs were originally built as prerequisites of
`medium-equivalence-outputs`, then rooted separately. Retained links above point
to these immutable observations; current definitions include the later collector
fix, so rebuilding the attributes is a new observation, not a report replay.

| Configuration | Immutable Test Output |
| --- | --- |
| Medium IA | `/nix/store/vn4v9q2fkdnbl7illdvipygfbcvr76ng-vm-test-run-laut-medium-equivalence-ia-sign` |
| Medium CA | `/nix/store/k90r3rjsdym8nji1hvh976zj5dzmzvb7-vm-test-run-laut-medium-equivalence-ca-sign` |
| Large IA | `/nix/store/f298lm02djxzh90pxx5p6svp1ygp46fm-vm-test-run-laut-large-equivalence-ia-sign` |
| Large CA | `/nix/store/xc3px0hwdc98d6ngha4wxs6bylqzwf5z-vm-test-run-laut-large-equivalence-ca-sign` |

To replay, set `IA` and `CA` to the immutable paths in the table:

```sh
nix develop -c python3 -B vm-tests/compare-experiments.py \
  --left "$IA/experiment/builderA/laut-experiment" \
  --right "$CA/experiment/builderA/laut-experiment" \
  --left-cache "$IA/cache" --right-cache "$CA/cache" \
  --output /tmp/opencode/laut-replay-ia-ca-A
```

Use builder B on both sides for the other cross-mode report. For repeats, use
one configuration's builder A and builder B directories and the same cache on
both sides. Reports from the final comparator are under
`/tmp/opencode/laut-{medium,large}-strict-ca-{ia-repeat,ca-repeat,ia-ca-A,ia-ca-B}/`.
Repeat comparisons exit 0; all four cross-mode comparisons exit 1.

### Results

Both signing configurations completed on both builders for both sizes. Every
final report has complete requested signed evidence, zero collection/schema or
join errors, and no ambiguous, unmatched, or unpaired nodes.

| Diagnostic | Medium | Large |
| --- | --- | --- |
| Paired derivations | 154 | 250 |
| Ordinary rebuilt derivations | 77 | 157 |
| Metadata-only FOD boundaries | 77 | 93 |
| Ordinary nodes with equal output identities | 63 | 82 |
| Ordinary nodes with divergent output identities | 14 | 75 |
| Equal requested signed outputs | 83 | 109 |
| Divergent requested signed outputs | 17 | 98 |
| IA builder A/B repeat | All 154 nodes agree | All 250 nodes agree |
| CA builder A/B repeat | All 154 nodes agree | All 250 nodes agree |

The cross-mode classifications and claimed identity values are identical for
builders A and B. Every divergent output differs in all three signed identities.
All 154 medium nodes also occur in large, with unchanged signed-output claims.
The ordinary nodes' normalized inputs differ in both sizes. The full comparator
still attributes the first recipe divergence to `bootstrap-tools` and marks
76/156 dependents blocked; those recipe statuses must not be mistaken for an
output-divergence frontier.

### Earliest Output Difference

Ignoring recipe-only blocking, the first output-divergent nodes are the same two
Bash recipes in medium and large:

| Requested Output | IA Derivation Basename | CA Derivation Basename |
| --- | --- | --- |
| `dev` | `qs1f2paqcg1nhyy9zi5clgp3annjvzv9-bash-5.2p37.drv` | `lc94hqi462wdwvjx60yaw8cirh7jkqcj-bash-5.2p37.drv` |
| `out` | `q9nx0s2c61r3cr70a5b7ghffdnfwwcfx-bash-5.2p37.drv` | `fsf5qqamqy47bn3xs474hza6l409568h-bash-5.2p37.drv` |

They have no output-divergent graph ancestors. After substituting native CA
self/dependency store hashes, each Bash `out` still differs in 37 ELF files:
`bin/bash` and 36 loadable builtins. The remaining bytes are exclusively GNU
build-ID descriptors. For the first recipe's sibling `out`, the executable IDs
are `f48d6b3975ba06902f09699d03f0e7bab0310c7d` (IA) and
`d96b1140aeb013b1d8ef588099bbed74e45133b2` (CA). Its `dev` NAR becomes byte-identical
after substituting its self-reference and four sibling-`out` references.

This is consistent with link-time build IDs hashing address-dependent inputs;
later path rewriting cannot normalize an opaque digest. The exact linker input
responsible has not yet been isolated. Do not strip build IDs in the signer to
manufacture equality. A focused common-recipe experiment controlling build IDs
would test this explanation while preserving the native-CA oracle.

The first libtool and autoreconf-hook outputs become byte-identical under native
reference substitutions. The large root `hello` also becomes byte-identical
after replacing its self hash and two glibc references (234,680-byte NAR, 47
files), but its signed synthetic/native identities still differ:

- Synthetic: `/nix/store/01m3g4wj6zff2pf6n7bqq5zl8r69rbcw-hello-2.12.1`.
- Native: `/nix/store/yk602gypn5ivi4jannfaxcf3wzh897q6-hello-2.12.1`.

Large introduces no new earliest graph-frontier mismatch. That does **not** prove
all downstream differences are inherited: 70 divergent nodes / 93 requested
outputs remain without a byte-level diagnosis. There may be additional local
causes behind the Bash frontier. The detailed local ledger is
`/tmp/opencode/laut-large-research-ledger.json`; content diagnostics are
`/tmp/opencode/laut-{medium,large}-*-content.json`.

### Validation And Limits

The final `experiment-tools` check passes lint and all 142 offline tests.
Fresh `small-equivalence-outputs` passes with both repeats and all four rebuilt
nodes' output identities equal on both builders:
`/nix/store/sdgv6bqighcgfnzi7zggfvsc6v689bsq-laut-small-equivalence-outputs`.
Medium/large diagnostic reports are deliberately red for real output differences;
the output-equality assertions remain strict. No production hashing fix was made.

These are extracted signed-claim comparisons, supplemented by targeted NAR
inspection, not signature authentication or complete source/content verification.
Ordinary medium/large verification checks and seeded variants were not run.
The mixed-addressing restriction, signature admission, and trust semantics are
unchanged. The larger tests therefore answer the original question negatively:
not all synthetic IA/native CA differences are accounted for yet.

## Build-ID Suppression Experiment

Following the medium/large Bash diagnosis, the agreed next experiment disables
build IDs rather than inventing a relocation-stable generator. This is a
diagnostic producer-side change, not a production hashing fix.

`nix/experiment-disable-build-ids.patch` replaces the pinned linker wrapper's
conditional SHA1 build-ID generation with a trailing `--build-id=none`. It
overrides explicit build-ID requests and applies to response-file and relocatable
links too. It does not remove notes from already-built binaries or affect linker
invocations that bypass this wrapper. Preloaded bootstrap binaries are unchanged.

All equivalence configurations use one patched copy of the pinned nixpkgs source,
including the early bootstrap wrappers, host-side FOD discovery, and in-VM
evaluation. Their manifests record the source path, original revision, and patch
name/hash. Ordinary signing/verification checks and infrastructure nixpkgs retain
their existing source. Nix, laut, the compiler random seed, and recipe hash-env
attributes are unchanged. The pinned separate-debug-info hook skips extraction
for binaries without a 40-digit ID, so build-ID-based debug lookup is deliberately
sacrificed. This experiment must not be described as preserving debug support.

Before rebuilding the workloads, the non-VM `experiment-build-id` check exercises
the original and patched wrapper scripts against the same infrastructure
toolchain. It demonstrates different SHA1 IDs for two RPATH addresses, absence of
IDs with the patch, complete ELF equality after the explicit address substitution,
and retained differences when code changes. It tests automatic and explicit ID
requests, ordinary and response-file invocation, and relocatable links.

```sh
nix build .#checks.x86_64-linux.experiment-build-id \
  .#checks.x86_64-linux.experiment-tools \
  --no-link --print-out-paths --max-jobs 1 --cores 4
```

Both checks pass, including all 142 offline experiment tests. The patch and test
are committed before fresh medium, then large, runs. Output equality remains
strict; source changes mean fresh observations, not a reinterpretation of the old
signed claims. Results are recorded below after the runs complete.
