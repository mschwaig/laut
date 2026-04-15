// =============================================================================
// Recursive memoized trust model verification for laut
// =============================================================================
//
// This module verifies that a dependency DAG is trustworthy under a recursive
// threshold trust model, checking that all intermediate build steps link up
// consistently by content hash.
//
// Two independent recursive structures are at play:
//
//   1. The dependency DAG — traversed bottom-up with memoization.
//      Each node (UDrvOutput) is visited exactly once.
//
//   2. The trust model tree — evaluated as a predicate over a set of keys.
//      This happens at each DAG node, but is a pure function call with
//      no memoization needed (trust model trees are tiny).
//
// These two structures don't interact recursively. The DAG traversal
// produces a HashSet<KeyId> of evidence per (output, content_hash), and
// the trust model evaluates that set. This is why flattening the trust
// model is unnecessary: the recursive enum IS the natural representation
// when your computation is recursive Rust code rather than Datalog.
//
// Flattening into (id, threshold, parent_id) tuples is an encoding
// concern for flat-relation engines like datafrog or Differential Dataflow.
// Here it would add complexity for no benefit.

use std::collections::{HashMap, HashSet};

// =============================================================================
// Types
// =============================================================================

// In production these would be interned u64 IDs via StringInterner.
// Using u64 here to stay close to the existing codebase.
type UDrv = u64;
type UDrvOutput = u64;
type RDrv = u64;
type ContentHash = u64;
type KeyId = u64;

// =============================================================================
// Trust model — the recursive access structure
// =============================================================================

#[derive(Clone, Debug)]
enum TrustModel {
    /// A leaf: trust a specific signing key.
    /// Satisfied when this key is in the evidence set.
    Key(KeyId),

    /// threshold(k, children): at least k children must be satisfied.
    /// Special cases:
    ///   threshold(1, [...])       = OR  (any one suffices)
    ///   threshold(len, [...])     = AND (all required)
    ///   threshold(2, [A, B])      = reproducibility (both must agree)
    ///   threshold(2, [A, B, C])   = 2-of-3 (any two suffice)
    Threshold(usize, Vec<TrustModel>),
}

impl TrustModel {
    /// Evaluate whether this trust model is satisfied by a set of available keys.
    ///
    /// This is a pure function — no side effects, no memoization needed.
    /// Trust model trees are small (a handful of nodes), so even repeated
    /// evaluation is cheap.
    fn satisfied_by(&self, available_keys: &HashSet<KeyId>) -> bool {
        match self {
            TrustModel::Key(k) => available_keys.contains(k),
            TrustModel::Threshold(t, children) => {
                let satisfied_count = children
                    .iter()
                    .filter(|child| child.satisfied_by(available_keys))
                    .count();
                satisfied_count >= *t
            }
        }
    }
}

// =============================================================================
// Facts — all input data, pre-indexed for efficient lookup
// =============================================================================

struct Facts {
    /// FOD outputs: udrv_output -> content_hash
    /// These are the leaves of the dependency DAG.
    fods: HashMap<UDrvOutput, ContentHash>,

    /// Which UDrv owns each output: udrv_output -> udrv
    output_to_udrv: HashMap<UDrvOutput, UDrv>,

    /// Which RDrvs resolve each UDrv: udrv -> [rdrv, ...]
    udrv_to_rdrvs: HashMap<UDrv, Vec<RDrv>>,

    /// How each RDrv resolves its dependencies:
    ///   rdrv -> [(dep_udrv_output, dep_content_hash), ...]
    ///
    /// This is the critical "linking up" data: for each dependency,
    /// the rdrv records which content hash it resolved that dependency to.
    rdrv_dep_resolutions: HashMap<RDrv, Vec<(UDrvOutput, ContentHash)>>,

    /// Build output claims:
    ///   (rdrv, udrv_output) -> [(content_hash, signing_key), ...]
    ///
    /// "Builder with key K claims that RDrv R produces content hash H
    ///  for output O."
    rdrv_output_claims: HashMap<(RDrv, UDrvOutput), Vec<(ContentHash, KeyId)>>,

    /// Which outputs each UDrv has: udrv -> [udrv_output, ...]
    udrv_outputs: HashMap<UDrv, Vec<UDrvOutput>>,
}

// =============================================================================
// Verification result
// =============================================================================

/// For each UDrvOutput, the set of ContentHashes that are verified under
/// the trust model. Typically this set has 0 or 1 elements.
/// It could have more than 1 if the trust model accepts multiple
/// incompatible content hashes (unusual but not impossible with OR-models).
type VerifiedOutputs = HashMap<UDrvOutput, HashSet<ContentHash>>;

// =============================================================================
// The verifier
// =============================================================================

struct Verifier<'a> {
    facts: &'a Facts,
    trust_model: &'a TrustModel,
    memo: VerifiedOutputs,
}

impl<'a> Verifier<'a> {
    fn new(facts: &'a Facts, trust_model: &'a TrustModel) -> Self {
        Verifier {
            facts,
            trust_model,
            memo: HashMap::new(),
        }
    }

    /// Verify a single UDrvOutput. Returns the set of content hashes
    /// that are verified for this output under the trust model.
    ///
    /// This is the core recursive function. It:
    ///   1. Checks the memo (already computed?)
    ///   2. Handles the base case (FODs)
    ///   3. For each RDrv that resolves the parent UDrv:
    ///      a. Recursively verifies all dependencies
    ///      b. Checks that the RDrv's dependency resolutions match
    ///      c. If all deps check out, collects the RDrv's output claims
    ///   4. Groups evidence by content hash
    ///   5. Evaluates the trust model for each candidate content hash
    ///   6. Memoizes and returns
    fn verify(&mut self, output: UDrvOutput) -> HashSet<ContentHash> {
        // Step 1: memo lookup — this is what makes DAGs efficient.
        // Without it, shared subgraphs (like glibc appearing in hundreds
        // of dependency paths) would be re-verified exponentially.
        if let Some(cached) = self.memo.get(&output) {
            return cached.clone();
        }

        // Insert empty set BEFORE recursing to handle cycles gracefully.
        // In a well-formed Nix dependency graph there are no cycles,
        // but this prevents infinite recursion if the input is malformed.
        // A cycle would just result in verification failure (empty set),
        // which is the safe default.
        self.memo.insert(output, HashSet::new());

        // Step 2: base case — FODs
        if let Some(&content_hash) = self.facts.fods.get(&output) {
            let result: HashSet<ContentHash> = [content_hash].into();
            self.memo.insert(output, result.clone());
            return result;
        }

        // Find the parent UDrv that owns this output
        let udrv = match self.facts.output_to_udrv.get(&output) {
            Some(&u) => u,
            None => return HashSet::new(), // orphaned output, can't verify
        };

        // Find all RDrvs that resolve this UDrv
        let rdrvs = match self.facts.udrv_to_rdrvs.get(&udrv) {
            Some(r) => r.clone(),
            None => return HashSet::new(), // no resolutions available
        };

        // Step 3: for each RDrv, check if its dependencies link up,
        // and collect evidence if they do.
        //
        // evidence maps: content_hash -> set of keys that provide evidence
        //
        // A key provides evidence for content_hash H if:
        //   - some rdrv claims (output -> H) signed by that key, AND
        //   - that rdrv's dependency resolutions ALL point to verified hashes
        let mut evidence: HashMap<ContentHash, HashSet<KeyId>> = HashMap::new();

        for rdrv in &rdrvs {
            // Step 3a: check ALL dependency resolutions
            let dep_resolutions = self
                .facts
                .rdrv_dep_resolutions
                .get(rdrv)
                .cloned()
                .unwrap_or_default();

            let all_deps_ok = dep_resolutions.iter().all(|(dep_out, dep_ch)| {
                // Recurse into the dependency.
                // This is where memoization pays off: if we've already
                // verified this dep_out (because another rdrv or another
                // path through the DAG already triggered it), we get
                // the cached result immediately.
                let verified_hashes = self.verify(*dep_out);
                verified_hashes.contains(dep_ch)
            });

            if !all_deps_ok {
                // This rdrv's dependency chain doesn't link up.
                // Skip it — its claims can't be used as evidence.
                continue;
            }

            // Step 3b: this rdrv is valid. Collect its claims for our output.
            let claims = self
                .facts
                .rdrv_output_claims
                .get(&(*rdrv, output))
                .cloned()
                .unwrap_or_default();

            for (content_hash, key) in claims {
                evidence.entry(content_hash).or_default().insert(key);
            }
        }

        // Step 4: evaluate the trust model for each candidate content hash.
        let mut verified = HashSet::new();
        for (content_hash, keys) in &evidence {
            if self.trust_model.satisfied_by(keys) {
                verified.insert(*content_hash);
            }
        }

        // Step 5: memoize and return.
        self.memo.insert(output, verified.clone());
        verified
    }

    /// Convenience: verify a UDrv by verifying all its outputs.
    /// Returns a map from output to verified content hashes.
    fn verify_udrv(&mut self, udrv: UDrv) -> HashMap<UDrvOutput, HashSet<ContentHash>> {
        let outputs = self
            .facts
            .udrv_outputs
            .get(&udrv)
            .cloned()
            .unwrap_or_default();

        outputs
            .into_iter()
            .map(|out| {
                let verified = self.verify(out);
                (out, verified)
            })
            .collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Convenience constants for readable test IDs
    const FOD1: UDrv = 1;
    const FOD1_OUT: UDrvOutput = 10;
    const HASH1: ContentHash = 100;

    const DEP1: UDrv = 2;
    const DEP1_OUT: UDrvOutput = 20;
    const BUILD_DEP1: ContentHash = 200;

    const OUTPUT1: UDrv = 3;
    const OUTPUT1_OUT: UDrvOutput = 30;
    const BUILD_OUTPUT1: ContentHash = 300;

    const RESOLVED_DEP1: RDrv = 1000;
    const RESOLVED_OUTPUT1: RDrv = 1001;

    const KEY1: KeyId = 9001;
    const KEY2: KeyId = 9002;
    const KEY3: KeyId = 9003;
    const KEY4: KeyId = 9004;

    /// Build the basic 3-node chain: FOD -> dep -> output
    fn base_facts() -> Facts {
        Facts {
            fods: [(FOD1_OUT, HASH1)].into(),
            output_to_udrv: [
                (FOD1_OUT, FOD1),
                (DEP1_OUT, DEP1),
                (OUTPUT1_OUT, OUTPUT1),
            ]
            .into(),
            udrv_to_rdrvs: [
                (DEP1, vec![RESOLVED_DEP1]),
                (OUTPUT1, vec![RESOLVED_OUTPUT1]),
            ]
            .into(),
            rdrv_dep_resolutions: [
                (RESOLVED_DEP1, vec![(FOD1_OUT, HASH1)]),
                (RESOLVED_OUTPUT1, vec![(DEP1_OUT, BUILD_DEP1)]),
            ]
            .into(),
            rdrv_output_claims: HashMap::new(), // filled per test
            udrv_outputs: [
                (FOD1, vec![FOD1_OUT]),
                (DEP1, vec![DEP1_OUT]),
                (OUTPUT1, vec![OUTPUT1_OUT]),
            ]
            .into(),
        }
    }

    // =========================================================================
    // Test 1: threshold(2, key1, key2) — both agree, everything links up
    // =========================================================================
    #[test]
    fn test_threshold_2_both_agree() {
        let mut facts = base_facts();
        facts.rdrv_output_claims = [
            ((RESOLVED_DEP1, DEP1_OUT), vec![
                (BUILD_DEP1, KEY1),
                (BUILD_DEP1, KEY2),
            ]),
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![
                (BUILD_OUTPUT1, KEY1),
                (BUILD_OUTPUT1, KEY2),
            ]),
        ]
        .into();

        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Key(KEY2),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(result.contains(&BUILD_OUTPUT1), "output should be verified");
    }

    // =========================================================================
    // Test 2: threshold(2, key1, key2) — builders disagree on intermediate step
    // =========================================================================
    //
    // Key1 builds dep1 -> BUILD_DEP1, key2 builds dep1 -> 999 (different!).
    // They agree on output1 -> BUILD_OUTPUT1, but the intermediate step
    // doesn't link up, so nothing should verify.
    #[test]
    fn test_intermediate_disagreement_fails() {
        let bad_dep_hash: ContentHash = 999;

        let mut facts = base_facts();
        facts.rdrv_output_claims = [
            ((RESOLVED_DEP1, DEP1_OUT), vec![
                (BUILD_DEP1, KEY1),
                (bad_dep_hash, KEY2), // KEY2 disagrees about dep1's output!
            ]),
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![
                (BUILD_OUTPUT1, KEY1),
                (BUILD_OUTPUT1, KEY2),
            ]),
        ]
        .into();

        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Key(KEY2),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);

        // dep1 should NOT be verified: only 1 key per content hash
        let dep_result = verifier.verify(DEP1_OUT);
        assert!(dep_result.is_empty(), "dep should not be verified — builders disagree");

        // output1 should NOT be verified either, because dep1 isn't verified,
        // so resolved_output1's dependency on dep1_out -> BUILD_DEP1 doesn't
        // link up (BUILD_DEP1 is not in the verified set for dep1_out).
        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(result.is_empty(), "output should not verify — dep chain is broken");
    }

    // =========================================================================
    // Test 3: different RDrvs, same output — should still verify
    // =========================================================================
    //
    // Key1 and key2 use different resolved derivations for dep1
    // (maybe different Nix versions), but both produce the same output hash.
    #[test]
    fn test_different_rdrvs_same_output() {
        const RESOLVED_DEP1_A: RDrv = 2000;
        const RESOLVED_DEP1_B: RDrv = 2001;

        let mut facts = base_facts();
        // Override: dep1 now has TWO rdrvs
        facts.udrv_to_rdrvs.insert(DEP1, vec![RESOLVED_DEP1_A, RESOLVED_DEP1_B]);
        facts.rdrv_dep_resolutions.insert(RESOLVED_DEP1_A, vec![(FOD1_OUT, HASH1)]);
        facts.rdrv_dep_resolutions.insert(RESOLVED_DEP1_B, vec![(FOD1_OUT, HASH1)]);
        // Remove the original rdrv's dep resolution
        facts.rdrv_dep_resolutions.remove(&RESOLVED_DEP1);

        facts.rdrv_output_claims = [
            // Key1 built via rdrv A, key2 built via rdrv B
            // Both produced the same content hash for dep1
            ((RESOLVED_DEP1_A, DEP1_OUT), vec![(BUILD_DEP1, KEY1)]),
            ((RESOLVED_DEP1_B, DEP1_OUT), vec![(BUILD_DEP1, KEY2)]),
            // Both agree on output1 too
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![
                (BUILD_OUTPUT1, KEY1),
                (BUILD_OUTPUT1, KEY2),
            ]),
        ]
        .into();

        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Key(KEY2),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(
            result.contains(&BUILD_OUTPUT1),
            "should verify — different paths, same output"
        );
    }

    // =========================================================================
    // Test 4: threshold(1, ...) — OR model, any single signer suffices
    // =========================================================================
    #[test]
    fn test_threshold_1_or_model() {
        let mut facts = base_facts();
        facts.rdrv_output_claims = [
            // Only key1 signed dep1
            ((RESOLVED_DEP1, DEP1_OUT), vec![(BUILD_DEP1, KEY1)]),
            // Only key2 signed output1
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![(BUILD_OUTPUT1, KEY2)]),
        ]
        .into();

        let trust_model = TrustModel::Threshold(1, vec![
            TrustModel::Key(KEY1),
            TrustModel::Key(KEY2),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(result.contains(&BUILD_OUTPUT1), "OR model: one signer suffices per step");
    }

    // =========================================================================
    // Test 5: nested trust model
    //   threshold(2, key1, threshold(1, key3, key4))
    //   = "key1 AND (key3 OR key4)"
    // =========================================================================
    #[test]
    fn test_nested_threshold() {
        let mut facts = base_facts();
        facts.rdrv_output_claims = [
            ((RESOLVED_DEP1, DEP1_OUT), vec![
                (BUILD_DEP1, KEY1),
                (BUILD_DEP1, KEY3), // key3 from the inner threshold
            ]),
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![
                (BUILD_OUTPUT1, KEY1),
                (BUILD_OUTPUT1, KEY4), // key4 from the inner threshold
            ]),
        ]
        .into();

        // threshold(2, key1, threshold(1, key3, key4))
        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Threshold(1, vec![
                TrustModel::Key(KEY3),
                TrustModel::Key(KEY4),
            ]),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(
            result.contains(&BUILD_OUTPUT1),
            "nested: key1 ✓, inner threshold satisfied by key4 ✓, so 2/2 met"
        );
    }

    // =========================================================================
    // Test 6: nested trust model — inner threshold NOT met
    // =========================================================================
    #[test]
    fn test_nested_threshold_inner_not_met() {
        let mut facts = base_facts();
        facts.rdrv_output_claims = [
            ((RESOLVED_DEP1, DEP1_OUT), vec![
                (BUILD_DEP1, KEY1),
                (BUILD_DEP1, KEY2), // key2 is NOT in the trust model at all
            ]),
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![
                (BUILD_OUTPUT1, KEY1),
                (BUILD_OUTPUT1, KEY2),
            ]),
        ]
        .into();

        // threshold(2, key1, threshold(1, key3, key4))
        // key2 is not key3 or key4, so the inner threshold is not met
        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Threshold(1, vec![
                TrustModel::Key(KEY3),
                TrustModel::Key(KEY4),
            ]),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(
            result.is_empty(),
            "nested: key1 ✓, but inner threshold not met (key2 is not key3 or key4)"
        );
    }

    // =========================================================================
    // Test 7: self-build only — Key(self)
    // =========================================================================
    #[test]
    fn test_self_build_only() {
        let self_key: KeyId = 42;

        let mut facts = base_facts();
        facts.rdrv_output_claims = [
            ((RESOLVED_DEP1, DEP1_OUT), vec![(BUILD_DEP1, self_key)]),
            ((RESOLVED_OUTPUT1, OUTPUT1_OUT), vec![(BUILD_OUTPUT1, self_key)]),
        ]
        .into();

        let trust_model = TrustModel::Key(self_key);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(result.contains(&BUILD_OUTPUT1));
    }

    // =========================================================================
    // Test 8: DAG (not tree) — shared dependency
    // =========================================================================
    //
    // Both dep1 and dep2 depend on the same FOD.
    // output1 depends on both dep1 and dep2.
    //
    //        FOD1
    //       /    \
    //     dep1   dep2
    //       \    /
    //       output1
    //
    // This tests that memoization works correctly with sharing.
    #[test]
    fn test_dag_shared_dependency() {
        const DEP2: UDrv = 4;
        const DEP2_OUT: UDrvOutput = 40;
        const BUILD_DEP2: ContentHash = 400;
        const RESOLVED_DEP2: RDrv = 1002;
        const RESOLVED_OUTPUT1_V2: RDrv = 1003;

        let facts = Facts {
            fods: [(FOD1_OUT, HASH1)].into(),
            output_to_udrv: [
                (FOD1_OUT, FOD1),
                (DEP1_OUT, DEP1),
                (DEP2_OUT, DEP2),
                (OUTPUT1_OUT, OUTPUT1),
            ]
            .into(),
            udrv_to_rdrvs: [
                (DEP1, vec![RESOLVED_DEP1]),
                (DEP2, vec![RESOLVED_DEP2]),
                (OUTPUT1, vec![RESOLVED_OUTPUT1_V2]),
            ]
            .into(),
            rdrv_dep_resolutions: [
                (RESOLVED_DEP1, vec![(FOD1_OUT, HASH1)]),
                (RESOLVED_DEP2, vec![(FOD1_OUT, HASH1)]),
                // output1 depends on BOTH dep1 and dep2
                (RESOLVED_OUTPUT1_V2, vec![
                    (DEP1_OUT, BUILD_DEP1),
                    (DEP2_OUT, BUILD_DEP2),
                ]),
            ]
            .into(),
            rdrv_output_claims: [
                ((RESOLVED_DEP1, DEP1_OUT), vec![
                    (BUILD_DEP1, KEY1),
                    (BUILD_DEP1, KEY2),
                ]),
                ((RESOLVED_DEP2, DEP2_OUT), vec![
                    (BUILD_DEP2, KEY1),
                    (BUILD_DEP2, KEY2),
                ]),
                ((RESOLVED_OUTPUT1_V2, OUTPUT1_OUT), vec![
                    (BUILD_OUTPUT1, KEY1),
                    (BUILD_OUTPUT1, KEY2),
                ]),
            ]
            .into(),
            udrv_outputs: [
                (FOD1, vec![FOD1_OUT]),
                (DEP1, vec![DEP1_OUT]),
                (DEP2, vec![DEP2_OUT]),
                (OUTPUT1, vec![OUTPUT1_OUT]),
            ]
            .into(),
        };

        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Key(KEY2),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(result.contains(&BUILD_OUTPUT1), "DAG with sharing should verify");

        // Also verify that FOD1 was only computed once by checking memo
        assert!(
            verifier.memo.contains_key(&FOD1_OUT),
            "FOD should be memoized"
        );
    }

    // =========================================================================
    // Test 9: DAG — one branch fails, whole thing fails
    // =========================================================================
    #[test]
    fn test_dag_one_branch_fails() {
        const DEP2: UDrv = 4;
        const DEP2_OUT: UDrvOutput = 40;
        const BUILD_DEP2: ContentHash = 400;
        const BUILD_DEP2_BAD: ContentHash = 401;
        const RESOLVED_DEP2: RDrv = 1002;
        const RESOLVED_OUTPUT1_V2: RDrv = 1003;

        let facts = Facts {
            fods: [(FOD1_OUT, HASH1)].into(),
            output_to_udrv: [
                (FOD1_OUT, FOD1),
                (DEP1_OUT, DEP1),
                (DEP2_OUT, DEP2),
                (OUTPUT1_OUT, OUTPUT1),
            ]
            .into(),
            udrv_to_rdrvs: [
                (DEP1, vec![RESOLVED_DEP1]),
                (DEP2, vec![RESOLVED_DEP2]),
                (OUTPUT1, vec![RESOLVED_OUTPUT1_V2]),
            ]
            .into(),
            rdrv_dep_resolutions: [
                (RESOLVED_DEP1, vec![(FOD1_OUT, HASH1)]),
                (RESOLVED_DEP2, vec![(FOD1_OUT, HASH1)]),
                // output1 expects dep2 -> BUILD_DEP2
                (RESOLVED_OUTPUT1_V2, vec![
                    (DEP1_OUT, BUILD_DEP1),
                    (DEP2_OUT, BUILD_DEP2),
                ]),
            ]
            .into(),
            rdrv_output_claims: [
                // dep1: both agree ✓
                ((RESOLVED_DEP1, DEP1_OUT), vec![
                    (BUILD_DEP1, KEY1),
                    (BUILD_DEP1, KEY2),
                ]),
                // dep2: builders DISAGREE ✗
                ((RESOLVED_DEP2, DEP2_OUT), vec![
                    (BUILD_DEP2, KEY1),
                    (BUILD_DEP2_BAD, KEY2), // different hash!
                ]),
                // output1: both agree on final, but it doesn't matter
                ((RESOLVED_OUTPUT1_V2, OUTPUT1_OUT), vec![
                    (BUILD_OUTPUT1, KEY1),
                    (BUILD_OUTPUT1, KEY2),
                ]),
            ]
            .into(),
            udrv_outputs: [
                (FOD1, vec![FOD1_OUT]),
                (DEP1, vec![DEP1_OUT]),
                (DEP2, vec![DEP2_OUT]),
                (OUTPUT1, vec![OUTPUT1_OUT]),
            ]
            .into(),
        };

        let trust_model = TrustModel::Threshold(2, vec![
            TrustModel::Key(KEY1),
            TrustModel::Key(KEY2),
        ]);

        let mut verifier = Verifier::new(&facts, &trust_model);

        // dep2 is not verified (builders disagree)
        let dep2_result = verifier.verify(DEP2_OUT);
        assert!(dep2_result.is_empty(), "dep2 should fail — disagreement");

        // output1 fails because dep2 isn't verified
        let mut verifier = Verifier::new(&facts, &trust_model);
        let result = verifier.verify(OUTPUT1_OUT);
        assert!(result.is_empty(), "output should fail — dep2 branch is broken");
    }
}