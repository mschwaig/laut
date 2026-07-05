# Verification Semantics

This document defines what it means to verify a *derivation output* under a
*trust model*. Italicised terms are defined in the
[project glossary](../README.md#glossary); when in doubt, look there first.

The mathematics is deliberately borrowed rather than invented. Trust models
denote *monotone access structures* in the sense of secret sharing.
Verification is a *disjoint-paths* condition on a graph built from signatures;
its dual formulation in terms of *cuts* is the max-flow/min-cut and Menger
circle of ideas. The feasibility check the implementation runs at merge points
is bipartite matching, i.e. Hall's marriage theorem. Readers at home in any of
these areas should find no private vocabulary in the corresponding parts.

## Setup

A *udrv* `D` describes one build step. *Dependency resolution* turns `D` into
a *rdrv* by replacing each dependency on another `D'`'s *derivation outputs*
with their specific *content hashes*. Executing the rdrv produces an *output
map*: a mapping from each of `D`'s *derivation output* names to that output's
*content hash*.

A *provenance log entry* is signed by one *builder* and records:
- the *resolved input hash* identifying a specific rdrv, and
- an output map the builder claims that rdrv produces.

The same rdrv may have multiple provenance log entries (one per signing
builder), and a builder may even sign multiple log entries for the same rdrv
with different output maps (i.e., disagree with themselves about what was
built).

An entry is a statement about a bitwise input/output relation and nothing
more. It does not matter how the builder came to possess the inputs — built
locally, substituted, or otherwise. This is what lets *verifiers* evaluate
trust models the builders never heard of, and it is what makes the *early
cutoff* optimization sound: artifacts are identified by content hash, so
entries from different builders compose wherever their bits agree.

A *verification target* is a pair `(D, S)` where:
- `D` is a *udrv*,
- `S` is a partial output map listing the subset of `D`'s *derivation
  outputs* the *verifier* cares about, each labelled with the required
  *content hash*.

## Trust models

A *trust model* `M` is a threshold tree, matching the implementation in
`laut-verify/src/verifier.rs`:

- `Key(k)` — a leaf naming a single trusted signing key.
- `Threshold(t, [M₁, …, Mₙ])` — an internal node, `1 ≤ t ≤ n`, satisfied by a
  key set when at least `t` of its children are.

**Well-formedness.** Each key appears in at most one leaf of the tree. Without
this, one key could satisfy several leaves at once and a threshold would count
the same signature more than once; with it, a set of keys determines exactly
which leaves it lights.

A threshold tree denotes a **monotone access structure**: the family of key
sets that satisfy it, called **qualified sets**. The family is upward closed
(*monotone*) — adding keys to a qualified set keeps it qualified — so adding
evidence can never retract a verification, and evaluating against all
available evidence is canonical. Everything below depends on `M` only through
its access structure.

Some canonical shapes:

- **Self-build only**: `Key(self)`.
- **Trusted cache (legacy)**: `Threshold(1, [Key(cache)])` — accept anything
  that cache signed (and see [Legacy signers](#legacy-signers) below).
- **Reproducibility, m-of-n**: `Threshold(m, [Key(a), Key(b), …])`. With
  `m = n` this is unanimous; with `m = 1` it is "any one of these signers
  suffices".
- **Nested**: `Threshold(2, [Key(self), Threshold(1, [Key(cache_a),
  Key(cache_b)])])` — "I built it AND at least one trusted cache agrees."

## The linkage graph

Fix a target `(D, S)`. All evidence lives in one directed graph.

- A **position** is a udrv in `D`'s dependency graph, including `D` itself.
  Positions and the dependency edges between them are fixed by `D`: every rdrv
  of a udrv resolves the same set of dependency positions, only to possibly
  different content hashes.
- The vertices at a position are the provenance log entries for rdrvs of that
  udrv. An entry `e` **links to** an entry `e'` at dependency position `u'`
  iff `e`'s rdrv resolves the outputs of `u'` to content hashes that `e'`'s
  output map produces (on exactly the named outputs — output maps are atomic,
  there is no mixing outputs across entries). An entry links to an *FOD* at
  `u'` iff its resolution matches the FOD's known output map.
- A **dependency path** is a maximal directed path in the position DAG from
  the target position down to a leaf.
- A **grounded path** along a dependency path `P` is a sequence of entries at
  the consecutive positions of `P`, each linked to the next, whose first
  entry's output map agrees with `S`, and which terminates at an FOD (or at a
  legacy-signed entry, see below).

## Semantics

A **witness family** for `(D, S)` along a dependency path `P` is a non-empty
set `W` of grounded paths along `P` such that at every position of `P`:

1. **No overcounting.** No two paths of `W` use entries with the same signer
   at that position. A signer may carry different paths at different
   positions, but never two paths at one position. (Formally: unit vertex
   capacity after identifying, per position, all entries with the same
   signer.)
2. **Qualification.** The set of signers used by `W` at that position is a
   qualified set of `M`.

**Verification of `(D, S)` succeeds iff every dependency path of the target
has a witness family.**

Spelled out:

- Since keys are unique in the model and paths are signer-disjoint per
  position, condition 2 says: at every position the family presents `|W|`
  distinct signatures lighting a satisfying set of leaves. Evidence is counted
  per signature per position — never per key across positions, never per
  reachable claim.
- For a flat model `Threshold(t, [Key(k₁), …, Key(kₙ)])`, discard entries
  signed by keys outside the model; a witness family is then exactly `t`
  vertex-disjoint grounded paths, and by **Menger's theorem** (equivalently,
  max-flow/min-cut with unit vertex capacities) one exists iff **every cut of
  the linkage graph contains at least `t` per-position signings**. The cut
  form is the right mental model: the trust model must hold across every
  frontier separating the inputs from the target, not merely at each position.
- Per-position checking — "at each udrv, do the signers of reachable, grounded
  entries form a qualified set?" — inspects only the single-position
  (*vertical*) cuts. The cuts it misses mix positions; the worked example
  below has all vertical cuts of size 3 and a diagonal cut of size 2.
- FODs ground paths and contribute no signers; the trust we place in them is
  what defines an FOD. A target that is itself an FOD verifies trivially.

## Worked example

Chain `F → A → B → C`, model `Threshold(3, [k₁, k₂, k₃])`. Builders k₁ and k₂
each build the whole chain; the intermediate steps do not reproduce (k₁
obtains a₁, b₁; k₂ obtains a₂, b₂) but both converge on the same final output
c. Builder k₃ co-signs a₁ (agreeing with k₁), b₂ (agreeing with k₂), and
c-from-b₁ (agreeing with k₁).

| position | entry        | signers  |
|----------|--------------|----------|
| A        | a₁           | k₁, k₃   |
| A        | a₂           | k₂       |
| B        | b₁ (from a₁) | k₁       |
| B        | b₂ (from a₂) | k₂, k₃   |
| C        | c (from b₁)  | k₁, k₃   |
| C        | c (from b₂)  | k₂       |

Every position sees all three signers, so per-position checking accepts. But
no witness family of size 3 exists: any grounded path through b₁ uses k₁ at B,
and any through b₂ uses k₂ at A. The cut { k₁'s signing of b₁, k₂'s signing of
a₂ } has size 2, so by Menger at most 2 disjoint paths exist. Verification
fails under `Threshold(3, …)` and succeeds under `Threshold(2, …)`.

k₃'s signatures corroborate individual steps but never a linked route from
inputs to target, and the semantics prices them accordingly: they add routing
options at width 2, and no width beyond it.

## Granularity invariance

Where one build step ends and the next begins is an artifact of packaging.
The semantics is invariant under redrawing those boundaries.

**Proposition.** Let `R` be a region — a contiguous run of positions along a
dependency path. The verdict depends on the entries inside `R` only through
`R`'s boundary behavior: for a flat model, the single number
max-flow-through-`R` (its **boundary capacity**); for nested models, the set
of signer profiles realizable across it.

Both directions of boundary-redrawing behave correctly:

- **Merging.** Had `R` been packaged as one opaque step, the builders able to
  sign the composite entry are those that executed a coherent chain through
  `R` — and each such builder's entries already form a linked single-signer
  path through the split presentation, contributing 1 to boundary capacity
  either way. Divergence that reconverges inside `R` is invisible at the
  boundary in both presentations. In the worked example, merging A, B, C into
  one step leaves k₃ with nothing it could sign, and the composite step
  carries exactly the width 2 that the fine-grained min-cut reports.
  Per-position checking is *not* invariant on this example (it answers 3 fine-
  grained, 2 merged); the disjoint-paths semantics answers 2 in both.
- **Splitting** never lowers the verdict — a composite entry maps to linked
  same-signer entries for the parts — and it can raise it, because partial
  contributions (one builder did the first half, another the second, meeting
  at a bitwise-identical artifact) become expressible. That is desirable, and
  it is the same bitwise-identity principle that early cutoff rests on.

This is also the implementation's licence to treat regions as opaque: since
the verdict depends on a reproducible region (one route, stable signer sets)
only through its boundary behavior, a verifier may pass through it without
case analysis — the search below does so implicitly, its state staying
constant across such regions — and the more careful matching is only needed
around observed divergence.

## Consequences

**Aggregation is at the udrv, not the *derivation output*.** A provenance log
entry covers a rdrv's entire output map as a single atomic claim. A downstream
rdrv that depends on multiple outputs of an upstream udrv must back all of
them with a single output map from one entry — no mix-and-match across
builders for different outputs of the same upstream build step.

**Each signer contributes at most one signature per position.** A builder who
signed several divergent entries at the same position adds routing options for
the family, not width. This is the rule that keeps a single builder from
inflating their own evidence by submitting multiple claims.

**Intermediate divergence is admitted when it converges downstream.** Two
builders may take different routes through non-reproducible intermediate steps
and reconverge; their grounded paths are disjoint and both count. The witness
family makes precise what per-position checking only approximated.

**Cross-linking is admitted.** Paths may change signers from position to
position: a builder may corroborate a step without having done the upstream
work itself, because artifacts are identified bitwise and entries compose on
content hashes. What the family guarantees is exactly this: at no cut is the
verification carried by fewer signatures than `M` demands.

**Family width is uniform along a path.** With mixed-arity ORs such as
`Threshold(1, [Key(k₁), Threshold(2, [Key(k₂), Key(k₃)])])`, a graph where one
position is covered only by k₁ (width 1) and another only by {k₂, k₃} (width
2) does not verify: the two-signer corroboration at the second position would
funnel through the single signature at the first — precisely the overcounting
that condition 1 forbids.

**FODs ground the closure without contributing evidence.** An FOD's output is
known by definition; no entry is required to anchor it, it appears in no
position's signer set, and the access structure is not evaluated at it.

## Legacy signers

A *legacy signer* produces a *nix legacy signature*, which is conceptually a
provenance log entry whose identifier is an *unresolved input hash* rather
than a *resolved input hash*. The legacy signer takes responsibility for
however the underlying *trustfully-resolved derivation* was resolved,
including the resolution of its dependencies.

In graph terms: a legacy-signed entry is a ground vertex, like an FOD. A
grounded path may terminate at it; positions upstream of it are not visited by
that path.

To keep the meaning of a witness family unambiguous, legacy signers are
permitted only as direct children of an outermost `Threshold(1, [...])` in the
trust model — a flat OR at the very top. The trust model is then read as
"trust this legacy signer's word for the whole chain, OR satisfy the stricter
sub-model below."

## Implementation

The verifier in `laut-verify/src/verifier.rs` implements the witness search as
a single demand-driven pass from the target toward the inputs.

- **State.** The state at a position is a set of *alternative demand
  multisets*: each multiset lists, per path of a candidate family, the output
  subset that path's downstream entry requires here. Alternatives exist
  because family width and routing are chosen per dependency path; each path
  commits to one alternative. The search starts at the target with one
  alternative per viable family width (widths below the smallest qualified
  set's size are skipped).
- **Serving demands.** At each position, serving one demand multiset means
  choosing, per demand, a route — an rdrv whose matching entries continue
  upstream, or a legacy entry that terminates the path — and then an
  injective, qualified signer assignment across the demands. That assignment
  is a bipartite matching; per-route and per-position scalar counts are the
  two easy necessary conditions, and the failures strictly between them are
  failures of **Hall's condition**, which is why this is a matching (small,
  enumerated over signer bitmasks) and not a count. Each realizable choice
  induces the demand multisets for the dependency positions; a fully
  terminated family discharges everything upstream on that path.
- **Laziness and memoisation.** Entries that never link toward the target are
  never visited, and `(position, alternatives)` states are memoised, with a
  false-during-recursion guard so malformed cyclic inputs terminate. In a
  reproducible region there is one route and one alternative per width, so
  the state collapses and the pass is linear; route enumeration only branches
  across observed divergence. Verification cost scales with observed
  non-reproducibility, not with the size of the dependency tree.
