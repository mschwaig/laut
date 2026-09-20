# Synthetic IA / Native CA Equivalence Investigation

Status: investigation in progress, 2026-09-20. Signed-claim and exact-ATerm
comparisons now localize the first small-graph divergences. Commands and results
live in the [experiment runbook](ia-ca-experiments.md). The approach below is not
a fixed sequence of implementation steps.

## Goal and Boundaries

Work dependency-first through a real bootstrap build-time closure to establish
where laut's synthetic content-addressed (CA) representation of input-addressed
(IA) builds matches the corresponding native CA builds. Fix discrepancies with
preserved evidence and regression tests, rather than treating a successful
top-level verification as proof that the hashing implementation is correct.

The comparisons cover both normalized resolved derivations and output content
identities. IA signing and verification share synthetic hashing code, so their
agreement alone is not an independent check against native CA behavior.

- Keep the restriction against mixed IA/CA non-fixed-output dependency trees.
- Start with the existing small bootstrap closure in `vm-tests/default.nix`:
  seven repetitions of `stdenv.__bootPackages`, followed by `binutils`.
- Do not run medium or large VM tests locally without agreement.
- Build, maintain, and commit the experimental support before relying on its
  results to guide hashing fixes. Preserve focused regression cases as we go.
- Keep cross-mode comparisons diagnostic. They must not make IA evidence
  admissible as CA evidence or change the existing trust semantics.
- Do not preserve compatibility with interim signature or experiment formats.
  We are developing a first version; update producers, consumers, and fixtures
  together instead of accumulating compatibility branches.
- Treat fixed-output derivations (FODs) and source inputs as explicit boundaries,
  not as ordinary floating CA outputs whose addressing scheme can be replaced.

Matching outputs under selected seeds is evidence of reproducibility and
reference transparency for those trials. It is not a universal proof: references
that were not perturbed, unexercised behavior, or correlated nondeterminism can
escape the experiment. Hash equivalence also does not establish preservation of
all program behavior under relocation.

## Existing Building Blocks

- `laut-sign/src/ia_closure.rs` walks discovered output references and computes
  synthetic CA paths and rewritten-content identities. It currently scans
  against candidates from the derivation graph; some comments still describe
  discovery through Nix's registered references instead.
- `laut-sign/src/constructive_trace.rs` constructs resolved-input preimages.
  `laut-sign/src/sign.rs` supplies output identities and optional debug data.
- `--include-preimage` records the resolved or synthetic CA ATerm in signatures.
  The current envelope is Sigstore/DSSE, as described in the
  [provenance profile](slsa-provenance-v1.md), not the historical JWS envelope.
- `laut-verify/src/debug.rs` and `laut-verify/tests/debug_probe.rs` implement and
  test the existing corpus/preimage diff probe. It is triggered by signature
  lookup failures and matches candidates by derivation name, so it is not yet
  a systematic whole-closure comparison tool. Corpus extraction is diagnostic
  and does not authenticate the extracted evidence.
- Signing VM tests already export caches that verification tests consume without
  rebuilding the signing workload. The small IA and CA tests currently exercise
  their modes independently, not equality between the modes.

Use these implementations rather than creating a second synthetic hashing path.
Where useful, compare intermediate results against Nix independently, without
normalizing away a difference in the native CA result we are trying to explain.

## Controlled Build Variants

Each configuration must be built in a separate signing-side VM test. Do not run
the different addressing/seed configurations inside one signing test. Export
independently reusable artifacts so that a change to one configuration need not
rebuild the others.

| Configuration | Purpose |
| --- | --- |
| Unseeded IA | Ordinary baseline for synthetic hashing |
| IA with seed A | Perturb store addresses throughout the graph |
| IA with seed B | Exercise a second address perturbation |
| Unseeded native CA | Independent target for synthetic CA equivalence |

Use independent repeats of the same configuration to assess reproducibility,
especially when interpreting a cross-seed mismatch. Existing independent builder
machines may provide repeats if they really build without sharing results.
Reusing a cached VM-test result, substituting an output under investigation, or
requesting an already-valid output is not another build observation. Record
preloaded bootstrap/source artifacts separately from outputs actually rebuilt.

The variants use the same pinned Nix revision, package definitions, platform,
logical store directory, output names, and relevant build settings, varying only
the intended addressing/seed configuration. Apply bootstrap patches to the
common package source, not just one variant unless that difference is the
explicit subject of an experiment.

Each signing test should export its cache/signatures, debug preimages, closure
inventory, and experiment metadata, plus access to the output contents needed
for diagnosis. Consumers can accept those outputs separately. Cache composition
may be useful for future tests but is not required by this investigation.

## Seeding Prerequisites

The local `../nix` checkout provides `mschwaig/nix`'s `store-path-seeding` feature
at revision `40ab933003b7f0bc9fd9270fd95aca2d2dc34c24` when inspected. Enable
`store-path-seeding` and set `store-path-seed`; the empty seed is the baseline.
Use the patched Nix for the unseeded configurations too. The active host Nix did
not support the feature at inspection time.

Keep seeded execution inside the experiment VMs. Client and daemon settings
must agree, and each seed requires fresh evaluation, not reuse of another
configuration's instantiated derivation. Avoid cross-seed evaluation-cache reuse
and substitution of outputs being measured. Do not reconfigure the host daemon.

Seeding affects derivation, source, FOD, and output paths, not only ordinary IA
outputs. Laut currently preserves registered FOD paths unchanged. Establish a
common unseeded comparison namespace, including source/FOD correspondence,
before interpreting cross-seed hashes. This is an early investigation question,
not something the existing walker can be assumed to handle correctly.

Nix's recorded unseeded path, NAR hash, size, and reference set can help diagnose
the experiment. An unseeded NAR hash is not a synthetic CA address, and a recorded
canonical path need not exist on disk. Read contents at their actual paths.
At the inspected revision, recording can fail nonfatally and the extra
`path-info` JSON metadata is exposed through a local store, not a daemon-backed
remote store. Preserve warnings and explicitly report missing metadata; never
turn missing evidence into a successful comparison.

The package-under-test pin is
`979daf34c8cacebcd917d540070b52a3c2b9b16e`. The completed `../nixpkgs2` checkout
contains this commit but currently points elsewhere. Start a dedicated experiment
branch at the pin while preserving the existing branch. Preserve any bootstrap
fixes as reviewable patches or commits and make their exact source available to
the VM builds; an undocumented sibling-checkout modification is not sufficient.

## Dependency-First Comparison

Inventory the full build-time closure, including named outputs, source inputs,
and FOD boundaries. Distinguish it from the runtime-reference closure used by
synthetic content hashing: a build-time-only input still matters even if it does
not occur in the final output's runtime closure.

Pair corresponding nodes using graph relationships, recipe information, and
output names. Derivation names alone are not unique, and raw IA/CA derivation
paths are expected to differ. Preserve correspondence decisions and report
ambiguous or unmatched nodes rather than silently pairing them.

Start at the bootstrap leaves and advance through nodes whose dependencies are
understood. For each corresponding node/output, track separately:

- Dependency identity agreement and exact normalized resolved-derivation ATerms,
  including the references and name used to derive the resolved input hash.
- Same-configuration repeat agreement and cross-seed synthetic identity
  agreement. Stable repeats with a cross-seed difference suggest hidden
  references or other address-sensitive behavior, but do not prove either cause.
- Synthetic IA versus native CA output paths, final NAR hashes/sizes, and
  castore identities where available. A store-path digest, a self-masked NAR
  digest, and a final rewritten NAR digest are distinct comparison layers.
- Ordinary signature verification status, separately from content equivalence.

Inspect the earliest unexplained difference before attributing differences in
its dependents to new bugs. Mark downstream comparisons as blocked or inherited
differences, while continuing independent branches. A node is fully matched only
when its required comparisons and dependency prerequisites have evidence.

For output mismatches, inspect reference candidates, detected and Nix-registered
references, rewrite mappings, self-reference handling, canonical reference
ordering, and pass-1/pass-2 hashing intermediates as needed. For ATerm mismatches,
separate propagated dependency differences from local recipe normalization.
Use content diffs, decompression, or other targeted inspection to investigate
hidden references without quietly expanding the production scanner's semantics.

## Debugging Experience

Extend support incrementally around actual failures, with these capabilities as
the target rather than a requirement to build a large framework up front:

- Compare exported experiments explicitly, even when verification succeeds or
  fails for a reason other than a missing signature.
- Keep exact preimages alongside structural diffs. Preserve local evidence even
  when there is no candidate in the other corpus.
- Identify artifacts by experiment, node, output, and build attempt, avoiding
  collisions between same-name derivations or signatures for the same path.
- Produce a machine-readable result and a concise summary of the earliest
  divergences, blocked dependents, and ambiguous or missing comparisons.
- Capture enough context to rerun a comparison without rebuilding the closure.
  Keep large output artifacts in reusable test outputs or retained stores,
  rather than committing whole caches to git.
- Clearly distinguish authenticated claims, unauthenticated diagnostic data,
  and locally recomputed values. Never feed diagnostic matches into trust facts.

## Progress and Regression Discipline

Maintain a small results ledger alongside this plan as experiments begin. Each
entry should identify the question, revisions/patches, target, platform, seed,
build settings, rebuilt versus preloaded inputs, commands, artifact locations,
comparison results, and next unresolved cause. Artifact checksums or immutable
store paths should make the evidence identifiable.

Track matched, divergent, blocked, ambiguous, and untested nodes against a fixed
closure inventory, with output-level details and explicit exclusions. Keep
repeat, cross-seed, and native-CA comparison results separate. If a patch changes
the closure, record the new inventory rather than comparing misleading totals.
Success means expanding the dependency-closed set with demonstrated agreement,
not merely reducing the number of printed errors.

For each failure, preserve a small reproducer where feasible, classify it, fix
the responsible layer, and rerun the affected comparisons. The fix may belong
in laut, its compatibility dependency, Nix, nixpkgs, or the harness. Add focused
regression tests and commit coherent support/fix changes with ledger updates.
Retain resolved failures as tests instead of relying only on expensive rebuilds.

Use Rust tests for comparison and hashing cases, then the relevant small VM
checks for integration. Existing entry points include:

```sh
nix develop -c cargo test --workspace
nix develop -c cargo test --workspace --no-default-features
nix build .#checks.x86_64-linux.small-ca-sign
nix build .#checks.x86_64-linux.small-ca-verify
nix build .#checks.x86_64-linux.small-ia-sign
nix build .#checks.x86_64-linux.small-ia-verify
nix build .#checks.x86_64-linux.debug-probe
```

These are existing checks, not yet the seeded comparison matrix. Add the new
test entry points and reproduction commands here when implemented.

## Decision Points and Current State

The plan was committed first. Isolated build variants and artifact collection
are the first implementation slice, before changing hashing behavior. Seeded
FOD preparation preserves declared addressing methods and exports correspondence;
using that correspondence in synthetic hashing remains separate work.

If the real bootstrap is too expensive or opaque to diagnose, reduce the issue
to tiny derivations that exercise the same references, validate the tooling and
fix there, and return to the bootstrap. Such fixtures supplement rather than
replace the intended real-closure result.

Ask before broadening the addressing scope, launching medium/large local builds,
or making a major change in direction. Record unexpected blockers and revised
assumptions here; do not silently weaken the equivalence criterion to make the
report green.

- Planning: repository tooling and local seeding interfaces inspected; separate
  signing-side VM tests agreed; nixpkgs checkout availability confirmed.
- Implementation: one ATerm-based derivation reader, a pinned seeded Nix package,
  and four independent small signing configurations with per-builder artifacts.
  All four signing configurations succeeded. Repeat and recorded-unseeded
  metadata comparisons agree across the six-node small graph, comprising four
  rebuilt outputs and two preloaded FODs. These are observations, not yet a
  demonstration of synthetic/native CA equivalence.
- Diagnostic comparisons: per-builder signed output identities, resolved-input
  identities, and exact normalized ATerms now compare over the paired graph,
  retaining provenance and structural diffs even above blocked dependencies.
  All four configurations' repeats agree. Both IA/CA builder pairs and both
  baseline-to-seed comparisons first diverge at `bootstrap-tools`; three rebuilt
  dependents remain blocked and the two FODs remain metadata-only boundaries.
- Recipe cause: the pinned nixpkgs CA switch adds builder-visible
  `outputHashAlgo` and `outputHashMode` attributes absent from the IA recipe.
  These are not implied by native floating-CA outputs. Preserve the distinction,
  now covered by a Rust regression, rather than forcing preimage agreement.
- Output cause: the pinned Nix `RewritingSink` does not record self-reference
  positions although `HashModuloSink` still intends to hash them; the pinned
  laut compatibility implementation does hash positions. For `bootstrap-tools`,
  the complete IA/native NARs become identical by replacing the self hash alone,
  and the zero-masked hash exactly matches native CA's declared address. See the
  runbook for byte counts, hashes, immutable artifacts, and reproduction details.
- Native oracle: a tiny seven-case CA-only VM reproduces the missing-position
  failure independently of bootstrap recipes. The experimental Nix now carries a
  reviewable local backport on the same base revision; all 730 Nix store tests and
  all oracle comparisons pass. The oracle calls laut's existing hashing helpers,
  including a two-external-reference ordering/duplication control. Exact artifacts
  and patch provenance are in the runbook. No laut hashing, trust admission,
  mixed-regime restriction, host daemon, or sibling checkout was changed.
- Corrected matrix: all four small signing configurations rebuilt at `0c66b21`.
  Repeats and recorded-unseeded metadata agree. IA/CA output claims now agree
  completely at three rebuilt nodes; stdenv differs only in its path. Its 14
  omitted source references exactly explain that remaining path discrepancy,
  captured in a Rust characterization test. The bootstrap-tools recipe difference
  still blocks dependency-closed equivalence; cross-seed synthetic claims still
  differ. No medium/large local VM tests were run.
- Source-reference fix: `dc47dd5` changes production synthetic hashing. The ATerm
  summary preserves `inputSrcs`; signer and verifier share source-aware candidate
  construction, identity-preserving source/FOD boundaries, and canonical sorting
  of final reference paths. Both builders now show all three output identities
  equal at all four rebuilt nodes, enforced by `small-equivalence-outputs`.
  Small IA/CA verification VMs pass, as do 105 Rust tests in both feature modes.
  The only remaining exact ATerm differences are the two explicit CA hash-env
  attributes at each rebuilt node; no source/dependency/path differences remain.
- Next: control recipe environment differences via a common-source experiment
  patch. Do not erase environment fields to force agreement. Source/FOD seed
  normalization, cross-subtree opaque source/output contexts, and authentication
  of the diagnostic experiment claims remain separate unresolved work.
