# Verification Semantics

This document defines what it means to verify a *derivation output* under a *trust model*. Italicised terms are defined in the [project glossary](../README.md#glossary); when in doubt, look there first.

## Setup

A *udrv* `D` describes one build step. *Dependency resolution* turns `D` into a *rdrv* by replacing each dependency on another `D'`'s *derivation outputs* with their specific *content hashes*. Executing the rdrv produces an *output map*: a mapping from each of `D`'s *derivation output* names to that output's *content hash*.

A *provenance log entry* is signed by one *builder* and records:
- the *resolved input hash* identifying a specific rdrv, and
- an output map the builder claims that rdrv produces.

The same rdrv may have multiple provenance log entries (one per signing builder), and a builder may even sign multiple log entries for the same rdrv with different output maps (i.e., disagree with themselves about what was built).

A *verification target* is a pair `(D, S)` where:
- `D` is a *udrv*,
- `S` is a partial output map listing the subset of `D`'s *derivation outputs* the *verifier* cares about, each labelled with the required *content hash*.

## Trust models

A *trust model* `M` is a recursive structure with two node kinds, matching the implementation in `rust/src/verifier.rs`:

- `Key(k)` — a leaf naming a single trusted signing key.
- `Threshold(t, [M₁, …, Mₙ])` — an internal node combining `n` sub-models via a *threshold function*. Children may themselves be `Key` leaves or further `Threshold` nodes.

Evaluation is a pure predicate over a set `S` of signing keys:

- `Key(k).satisfied_by(S)` ⇔ `k ∈ S`.
- `Threshold(t, [M₁, …, Mₙ]).satisfied_by(S)` ⇔ at least `t` of the sub-models `Mᵢ` are themselves satisfied by `S`.

The predicate is monotone in `S`: enlarging `S` can never move a sub-model from satisfied to unsatisfied. This is what makes "take the maximal bundle" the right strategy below — adding more evidence cannot retract a verification.

Some canonical shapes:

- **Self-build only**: `Key(self)`.
- **Trusted cache (legacy)**: `Threshold(1, [Key(cache)])` — accept anything that cache signed (and see [Legacy signers](#legacy-signers) below).
- **Reproducibility, m-of-n**: `Threshold(m, [Key(a), Key(b), …])`. With `m = n` this is unanimous; with `m = 1` it is "any one of these signers suffices".
- **Nested**: `Threshold(2, [Key(self), Threshold(1, [Key(cache_a), Key(cache_b)])])` — "I built it AND at least one trusted cache agrees."

## Semantics

A *bundle* is a set of provenance log entries.

Verification of target `(D, S)` succeeds iff there exists a bundle `B` such that:

**Closure.**
1. Some entry in `B` is for a rdrv of `D`, and its output map agrees with `S` on every *derivation output* `S` specifies.
2. For every entry in `B`, every dependency named in its rdrv's *dependency resolution* either matches an *FOD*'s known output, or matches the output map of some other entry in `B` on the named outputs.

**Trust.**
3. For every udrv `D'` that some entry in `B` is for, the *trust model* is satisfied by the set of signers across entries-in-`B` whose rdrv is a rdrv of `D'`.

If any such bundle exists, the target is verified. The verifier computes the *maximal* bundle — the union of every entry that participates in any closure reaching `(D, S)`. The trust model is monotone, so leaving entries out can never enable a verification the maximal bundle doesn't already enable.

## Consequences

**Aggregation is at the udrv, not the *derivation output*.** A provenance log entry covers a rdrv's entire output map as a single atomic claim. A downstream rdrv that depends on multiple outputs of an upstream udrv must back all of them with a single output map from one entry — there is no mix-and-match across builders for different outputs of the same upstream build step.

**Each signer counts once per udrv.** At each udrv covered by `B`, the signers are deduplicated. A builder who signed two divergent entries for the same udrv (different output maps) still contributes weight one to that udrv's *threshold function* check. This is the rule that keeps a single builder from inflating their own evidence by submitting multiple contradictory claims.

**Intermediate divergence is admitted when it converges downstream.** Two builders may sign entries for distinct rdrvs of the same intermediate udrv (claiming different *content hashes* for its outputs), and downstream rdrvs may resolve that udrv to one of those content hashes or the other. All such upstream entries are in `B` as long as they are reached from the target by the closure, and the intermediate udrv's evidence is the union of both signers. The trust model is checked against the union — it does not care that the entries disagree on what was produced.

**FODs ground the closure without contributing evidence.** An *FOD*'s output is known by definition; no entry is required to anchor it. FODs do not appear in any udrv's evidence and the trust model is not evaluated at them.

## Legacy signers

A *legacy signer* produces a *nix legacy signature*, which is conceptually a provenance log entry whose identifier is an *unresolved input hash* rather than a *resolved input hash*. The legacy signer takes responsibility for however the underlying *trustfully-resolved derivation* was resolved, including the resolution of its dependencies.

In bundle terms: a legacy entry's rdrv-side closure obligation is waived. Whatever its dependencies, those dependencies do not need to be in `B`. The closure terminates at this entry.

To keep the meaning of `B` unambiguous, legacy signers are permitted only as direct children of an outermost `Threshold(1, [...])` in the *trust model* — a flat OR at the very top. The trust model is then read as "trust this legacy signer's word for the whole chain, OR satisfy the stricter sub-model below."

## Implementation

The verifier in `rust/src/verifier.rs` computes the maximal bundle in two passes over the provenance log entries fed in from the verification pipeline:

1. **`supports(D', S')`** — bottom-up, memoised. True iff some closure exists from FODs to `(D', S')`. For an FOD: match `S'` against the FOD's known output map. Otherwise: look for some provenance log entry for a rdrv of `D'` whose output map agrees with `S'` and whose rdrv's *dependency resolution* groups into per-dependency subsets that all themselves *support*.

2. **Reachable traversal from the target** — top-down. Starts at `(D, S)`; walks every in-bundle entry. An entry is *in-bundle* iff its `(udrv, subset)` is reachable from the target and either its rdrv's *dependency resolution* supports or it was signed by a legacy signer. Each in-bundle entry contributes its signer to the evidence at its udrv.

A final check evaluates the trust model at every udrv that has any evidence. The target's own udrv must additionally have at least one in-bundle entry (otherwise an empty bundle would vacuously satisfy condition 3).

The two passes are linear in the size of the supported and reachable sub-graph; no path enumeration is involved.
