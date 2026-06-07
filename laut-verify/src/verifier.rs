//! Trust-model verification for laut.
//!
//! A verification target is a pair `(udrv, output_subset)` where `output_subset` lists the
//! outputs of `udrv` the caller cares about along with the content hashes they should have.
//! Verification succeeds iff there exists a bundle of FOD-to-target threads through the
//! resolved DAG such that, at every udrv position p that some thread passes through, the
//! set of distinct keys used at p satisfies the trust model. Each key counts weight 1 per
//! position regardless of how many threads pass through it (this is what permits the
//! divergence-then-merge case without double counting).
//!
//! The implementation is a two-pass algorithm with no per-memo evidence accumulation:
//!
//!   1. `supports(udrv, subset)`: bottom-up, memoized. True iff there is at least one
//!      valid FOD-to-here thread. An interior position supports iff some rdrv-claim
//!      matches the subset and either that claim is signed by a legacy key (which
//!      bypasses upstream linking) or every one of the rdrv's dep resolutions supports
//!      its own grouped subset.
//!
//!   2. From the target, walk down through in-bundle rdrv-claims. A claim is "in-bundle"
//!      iff its `(udrv, subset)` is reachable from the target and its deps support (or
//!      the claim is legacy). Each in-bundle rdrv-claim contributes its signing key to
//!      `evidence[udrv]`. Non-legacy claims propagate reachability to their deps; legacy
//!      claims terminate the thread there.
//!
//! Finally, the trust model is evaluated against `evidence[p]` at every populated p.

use std::collections::{HashMap, HashSet};

use crate::string_interner::{ContentHash, KeyId, OutputName, RDrv, UDrv};

/// A recursive threshold-based trust model. `KeyLegacy` marks a key that
/// short-circuits the linking-up check at the point where it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustModel {
    Key(KeyId),
    KeyLegacy(KeyId),
    Threshold(usize, Vec<TrustModel>),
}

impl TrustModel {
    /// Pure monotone predicate over an evidence set.
    pub fn satisfied_by(&self, keys: &HashSet<KeyId>) -> bool {
        match self {
            TrustModel::Key(k) | TrustModel::KeyLegacy(k) => keys.contains(k),
            TrustModel::Threshold(t, children) => {
                let count = children.iter().filter(|c| c.satisfied_by(keys)).count();
                count >= *t
            }
        }
    }

    /// `KeyLegacy` may only appear as a direct child of a top-level `Threshold(1, ...)`.
    /// This is what makes the legacy short-circuit unambiguous: the user opts in to
    /// "trust this signer as-is" via an OR at the very root of the model.
    pub fn validate(&self) -> Result<HashSet<KeyId>, String> {
        let mut legacy = HashSet::new();
        match self {
            TrustModel::Key(_) => Ok(legacy),
            TrustModel::KeyLegacy(_) => Err(
                "KeyLegacy is only allowed as a child of a top-level Threshold(1, [...])".into(),
            ),
            TrustModel::Threshold(t, children) => {
                let has_legacy = children
                    .iter()
                    .any(|c| matches!(c, TrustModel::KeyLegacy(_)));
                if has_legacy && *t != 1 {
                    return Err(format!(
                        "Trust model contains KeyLegacy children but top threshold is {} (must be 1)",
                        t
                    ));
                }
                for child in children {
                    match child {
                        TrustModel::KeyLegacy(k) => {
                            legacy.insert(*k);
                        }
                        other => {
                            ensure_no_legacy(other)?;
                        }
                    }
                }
                Ok(legacy)
            }
        }
    }
}

fn ensure_no_legacy(tm: &TrustModel) -> Result<(), String> {
    match tm {
        TrustModel::Key(_) => Ok(()),
        TrustModel::KeyLegacy(_) => {
            Err("KeyLegacy is only allowed at the top level of the trust model".into())
        }
        TrustModel::Threshold(_, children) => {
            for c in children {
                ensure_no_legacy(c)?;
            }
            Ok(())
        }
    }
}

/// A required output map for a udrv at a particular position in the DAG.
/// Stored as a sorted vector so it can be used as a HashMap key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Subset {
    entries: Vec<(OutputName, ContentHash)>,
}

impl Subset {
    pub fn from_pairs<I: IntoIterator<Item = (OutputName, ContentHash)>>(it: I) -> Self {
        let mut entries: Vec<_> = it.into_iter().collect();
        entries.sort();
        entries.dedup();
        Subset { entries }
    }

    pub fn entries(&self) -> &[(OutputName, ContentHash)] {
        &self.entries
    }

    /// `output_map` is "compatible" with this subset iff it produces every output
    /// the subset requires with the exact content hash the subset requires. The
    /// output_map may produce additional outputs; we don't care about those here.
    pub fn matches_output_map(&self, output_map: &HashMap<OutputName, ContentHash>) -> bool {
        self.entries
            .iter()
            .all(|(o, c)| output_map.get(o) == Some(c))
    }
}

/// A single signing of an rdrv. Multiple `RdrvClaim`s may exist for the same rdrv
/// (different signers; or the same signer who disagrees with themselves across
/// distinct signings — divergence at this build step).
#[derive(Clone, Debug)]
pub struct RdrvClaim {
    pub signer: KeyId,
    pub output_map: HashMap<OutputName, ContentHash>,
}

/// All input data the verifier reasons about, pre-indexed for the two passes.
/// The Python boundary builds this incrementally before calling `verify`.
#[derive(Debug, Default)]
pub struct Facts {
    /// FOD outputs, keyed by udrv. FODs are the leaves of the DAG.
    pub fods: HashMap<UDrv, HashMap<OutputName, ContentHash>>,

    /// Which udrv each rdrv resolves.
    pub rdrv_resolves: HashMap<RDrv, UDrv>,

    /// Inverted index: which rdrvs resolve each udrv.
    pub udrv_to_rdrvs: HashMap<UDrv, Vec<RDrv>>,

    /// Each rdrv's dep resolutions, grouped by dep udrv so the verifier can ask
    /// "what subset of dep udrv does this rdrv require?" in one lookup.
    pub rdrv_dep_subsets: HashMap<RDrv, Vec<(UDrv, Subset)>>,

    /// Signed claims per rdrv. Each entry is one signing.
    pub rdrv_claims: HashMap<RDrv, Vec<RdrvClaim>>,
}

impl Facts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_fod(&mut self, udrv: UDrv, outputs: HashMap<OutputName, ContentHash>) {
        self.fods.insert(udrv, outputs);
    }

    /// Record that `rdrv` resolves `udrv` and how it resolved each of its deps.
    /// `dep_resolutions` is the flat (dep_udrv, output_name) -> content_hash map
    /// as it arrives from the Python boundary; this method groups it by dep_udrv.
    pub fn add_rdrv(
        &mut self,
        rdrv: RDrv,
        udrv: UDrv,
        dep_resolutions: HashMap<(UDrv, OutputName), ContentHash>,
    ) {
        self.rdrv_resolves.insert(rdrv, udrv);
        self.udrv_to_rdrvs.entry(udrv).or_default().push(rdrv);

        let mut grouped: HashMap<UDrv, Vec<(OutputName, ContentHash)>> = HashMap::new();
        for ((dep_udrv, output_name), content_hash) in dep_resolutions {
            grouped
                .entry(dep_udrv)
                .or_default()
                .push((output_name, content_hash));
        }
        let dep_subsets: Vec<(UDrv, Subset)> = grouped
            .into_iter()
            .map(|(dep_udrv, pairs)| (dep_udrv, Subset::from_pairs(pairs)))
            .collect();
        self.rdrv_dep_subsets.insert(rdrv, dep_subsets);
    }

    pub fn add_claim(
        &mut self,
        rdrv: RDrv,
        signer: KeyId,
        output_map: HashMap<OutputName, ContentHash>,
    ) {
        self.rdrv_claims
            .entry(rdrv)
            .or_default()
            .push(RdrvClaim { signer, output_map });
    }
}

/// The verifier holds borrowed references to the facts and trust model and a
/// supports-memo built up during a single call.
pub struct Verifier<'a> {
    facts: &'a Facts,
    trust_model: &'a TrustModel,
    legacy_keys: HashSet<KeyId>,

    /// Memo for the bottom-up `supports` pass. The default-false-during-recursion
    /// idiom prevents infinite recursion on malformed cyclic inputs.
    supports_memo: HashMap<(UDrv, Subset), bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub verified: bool,
    /// Evidence collected at each udrv position. Useful for debugging.
    pub evidence: HashMap<UDrv, HashSet<KeyId>>,
    /// All `(udrv, subset)` pairs that ended up in-bundle. Useful for debugging.
    pub reachable: HashSet<(UDrv, Subset)>,
}

impl<'a> Verifier<'a> {
    pub fn new(facts: &'a Facts, trust_model: &'a TrustModel) -> Result<Self, String> {
        let legacy_keys = trust_model.validate()?;
        Ok(Verifier {
            facts,
            trust_model,
            legacy_keys,
            supports_memo: HashMap::new(),
        })
    }

    /// Verify that some bundle of threads exists supporting `(target_udrv, target_subset)`
    /// such that the trust model is satisfied at every populated position.
    pub fn verify(&mut self, target_udrv: UDrv, target_subset: Subset) -> VerifyResult {
        let mut result = VerifyResult {
            verified: false,
            evidence: HashMap::new(),
            reachable: HashSet::new(),
        };

        // If nothing supports the target, no bundle exists.
        if !self.supports(target_udrv, &target_subset) {
            return result;
        }

        result
            .reachable
            .insert((target_udrv, target_subset.clone()));
        let mut worklist = vec![(target_udrv, target_subset.clone())];

        while let Some((udrv, subset)) = worklist.pop() {
            // FODs contribute no evidence and have no deps; the trust we place in
            // them is what defines a FOD.
            if self.facts.fods.contains_key(&udrv) {
                continue;
            }

            let Some(rdrvs) = self.facts.udrv_to_rdrvs.get(&udrv) else {
                continue;
            };

            for &rdrv in rdrvs {
                let Some(claims) = self.facts.rdrv_claims.get(&rdrv) else {
                    continue;
                };

                let empty_deps = Vec::new();
                let dep_subsets = self
                    .facts
                    .rdrv_dep_subsets
                    .get(&rdrv)
                    .unwrap_or(&empty_deps);

                // Compute once per rdrv: do all this rdrv's deps support?
                // Used by every non-legacy claim at this rdrv.
                let deps_supported = dep_subsets
                    .iter()
                    .all(|(dep_udrv, dep_subset)| self.supports(*dep_udrv, dep_subset));

                for claim in claims {
                    if !subset.matches_output_map(&claim.output_map) {
                        continue;
                    }

                    let is_legacy = self.legacy_keys.contains(&claim.signer);
                    let claim_valid = is_legacy || deps_supported;
                    if !claim_valid {
                        continue;
                    }

                    result
                        .evidence
                        .entry(udrv)
                        .or_default()
                        .insert(claim.signer);

                    // Legacy claims don't propagate upstream — their thread terminates here.
                    if !is_legacy {
                        for (dep_udrv, dep_subset) in dep_subsets {
                            if result.reachable.insert((*dep_udrv, dep_subset.clone())) {
                                worklist.push((*dep_udrv, dep_subset.clone()));
                            }
                        }
                    }
                }
            }
        }

        // The trust model must be satisfied at every populated position.
        let model_ok = result
            .evidence
            .values()
            .all(|keys| self.trust_model.satisfied_by(keys));

        // The target position itself must have evidence (unless the target is a FOD).
        // Without this, a target whose deps all support but which has no signed
        // claims would vacuously "pass" because the evidence map is empty.
        let target_covered = self.facts.fods.contains_key(&target_udrv)
            || result.evidence.contains_key(&target_udrv);

        result.verified = model_ok && target_covered;
        result
    }

    fn supports(&mut self, udrv: UDrv, subset: &Subset) -> bool {
        let key = (udrv, subset.clone());
        if let Some(&cached) = self.supports_memo.get(&key) {
            return cached;
        }
        // Set false before recursing so cycles in malformed input terminate.
        self.supports_memo.insert(key.clone(), false);
        let result = self.compute_supports(udrv, subset);
        self.supports_memo.insert(key, result);
        result
    }

    fn compute_supports(&mut self, udrv: UDrv, subset: &Subset) -> bool {
        if let Some(fod_outputs) = self.facts.fods.get(&udrv) {
            return subset.matches_output_map(fod_outputs);
        }

        let Some(rdrvs) = self.facts.udrv_to_rdrvs.get(&udrv).cloned() else {
            return false;
        };

        for rdrv in rdrvs {
            let Some(claims) = self.facts.rdrv_claims.get(&rdrv).cloned() else {
                continue;
            };

            let matching_claims: Vec<&RdrvClaim> = claims
                .iter()
                .filter(|c| subset.matches_output_map(&c.output_map))
                .collect();
            if matching_claims.is_empty() {
                continue;
            }

            // Legacy short-circuit: a legacy signing at this rdrv supports the
            // subset without needing to verify upstream.
            if matching_claims
                .iter()
                .any(|c| self.legacy_keys.contains(&c.signer))
            {
                return true;
            }

            let dep_subsets = self
                .facts
                .rdrv_dep_subsets
                .get(&rdrv)
                .cloned()
                .unwrap_or_default();
            let deps_ok = dep_subsets
                .iter()
                .all(|(dep_udrv, dep_subset)| self.supports(*dep_udrv, dep_subset));
            if deps_ok {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_subset(pairs: &[(OutputName, ContentHash)]) -> Subset {
        Subset::from_pairs(pairs.iter().copied())
    }

    fn make_output_map(pairs: &[(OutputName, ContentHash)]) -> HashMap<OutputName, ContentHash> {
        pairs.iter().copied().collect()
    }

    fn threshold(t: usize, keys: &[KeyId]) -> TrustModel {
        TrustModel::Threshold(t, keys.iter().map(|k| TrustModel::Key(*k)).collect())
    }

    // Distinct IDs for tests. We don't go through the interner so we can keep tests focused
    // on verifier behaviour.
    const F1: UDrv = UDrv(1);
    const A: UDrv = UDrv(2);
    const B: UDrv = UDrv(3);
    const C: UDrv = UDrv(4);

    const R_A_1: RDrv = RDrv(101);
    const R_A_2: RDrv = RDrv(102);
    const R_B_1: RDrv = RDrv(103);
    const R_B_2: RDrv = RDrv(104);
    const R_C_1: RDrv = RDrv(105);

    const OUT: OutputName = OutputName(200);
    const DEV: OutputName = OutputName(201);

    const HF: ContentHash = ContentHash(300);
    const HA: ContentHash = ContentHash(301);
    const HA2: ContentHash = ContentHash(302);
    const HB: ContentHash = ContentHash(303);
    const HC: ContentHash = ContentHash(304);
    const HDEV1: ContentHash = ContentHash(305);
    const HDEV2: ContentHash = ContentHash(306);

    const K1: KeyId = KeyId(400);
    const K2: KeyId = KeyId(401);
    const K3: KeyId = KeyId(402);
    const K_CACHE: KeyId = KeyId(403);

    /// Linear chain FOD -> A -> B with both keys signing every step, agreeing.
    /// Threshold(2) must verify.
    #[test]
    fn linear_chain_both_signers_agree() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_claim(R_A_1, K2, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(result.verified);
        assert_eq!(result.evidence[&A], [K1, K2].into());
        assert_eq!(result.evidence[&B], [K1, K2].into());
    }

    /// Intermediate disagreement that doesn't reconverge upstream: k2 builds A with HA2,
    /// but B's rdrv resolves A to HA. K2's A-signing isn't compatible with the rdrv at B,
    /// so it's not in-bundle. Evidence at A is {k1}, threshold(2) fails.
    #[test]
    fn intermediate_disagreement_no_convergence() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_A_2, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_2, K2, make_output_map(&[(OUT, HA2)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(!result.verified);
    }

    /// The convergence case: k1 and k2 disagree on A but each signs a B-rdrv that uses
    /// their own A. Both rdrvs at B produce the same HB. Both A-signings and both
    /// B-signings end up in the bundle; evidence at both positions is {k1, k2}.
    #[test]
    fn divergence_at_a_converges_at_b() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_A_2, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_2, K2, make_output_map(&[(OUT, HA2)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_rdrv(R_B_2, B, [((A, OUT), HA2)].into());
        facts.add_claim(R_B_2, K2, make_output_map(&[(OUT, HB)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(result.verified);
        assert_eq!(result.evidence[&A], [K1, K2].into());
        assert_eq!(result.evidence[&B], [K1, K2].into());
    }

    /// "No double counting at a position": k1 signs both divergent A claims, k2 doesn't
    /// sign anywhere at A. Both A subsets are reachable via B's two rdrvs (which k1 also
    /// signed). But evidence at A is just {k1}: k1 deduplicates across the two threads
    /// through (A, HA) and (A, HA2). Threshold(2) fails.
    #[test]
    fn no_double_counting_at_a_position() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_A_2, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_2, K1, make_output_map(&[(OUT, HA2)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));
        facts.add_rdrv(R_B_2, B, [((A, OUT), HA2)].into());
        facts.add_claim(R_B_2, K1, make_output_map(&[(OUT, HB)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(!result.verified);
        // Sanity-check: A position has only k1 worth of evidence.
        assert_eq!(result.evidence[&A], [K1].into());
    }

    /// Threshold(1) — any single signer suffices.
    #[test]
    fn threshold_one_or_model() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));

        let tm = threshold(1, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(result.verified);
    }

    /// Nested AND-of-(key, OR-of-keys): threshold(2, [k1, threshold(1, [k2, k3])]).
    #[test]
    fn nested_threshold() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_claim(R_A_1, K3, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K3, make_output_map(&[(OUT, HB)]));

        let tm = TrustModel::Threshold(
            2,
            vec![
                TrustModel::Key(K1),
                TrustModel::Threshold(1, vec![TrustModel::Key(K2), TrustModel::Key(K3)]),
            ],
        );
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(result.verified);
    }

    /// Multi-output udrv. Builders disagree on $dev but agree on $out. The verification
    /// target asks for $out only, and both builders' rdrvs are in-bundle because both
    /// produce the requested $out hash.
    #[test]
    fn multi_output_target_subset_ignores_dev_divergence() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        // k1 and k2 disagree on $dev but agree on $out
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA), (DEV, HDEV1)]));
        facts.add_claim(R_A_1, K2, make_output_map(&[(OUT, HA), (DEV, HDEV2)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(A, make_subset(&[(OUT, HA)]));
        assert!(
            result.verified,
            "target ignores $dev, both keys agree on $out"
        );
    }

    /// Multi-output udrv where the downstream rdrv resolves both outputs. The pair must
    /// come from the SAME signing — you can't mix-and-match k1's $out with k2's $dev.
    #[test]
    fn multi_output_downstream_requires_consistent_signing() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA), (DEV, HDEV1)]));
        facts.add_claim(R_A_1, K2, make_output_map(&[(OUT, HA), (DEV, HDEV2)]));

        // Downstream resolves both outputs of A, picking k1's view of $dev.
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA), ((A, DEV), HDEV1)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        // Only k1's A-signing matches the (out=HA, dev=HDEV1) requirement.
        // k2 disagreed on $dev so doesn't support B's deps. Evidence at A = {k1}.
        assert!(!result.verified);
        assert_eq!(result.evidence[&A], [K1].into());
    }

    /// DAG with sharing: FOD feeds into both A and a sibling that converges at C.
    #[test]
    fn dag_with_sharing() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_claim(R_A_1, K2, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_B_1, B, [((F1, OUT), HF)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));
        facts.add_rdrv(R_C_1, C, [((A, OUT), HA), ((B, OUT), HB)].into());
        facts.add_claim(R_C_1, K1, make_output_map(&[(OUT, HC)]));
        facts.add_claim(R_C_1, K2, make_output_map(&[(OUT, HC)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(C, make_subset(&[(OUT, HC)]));
        assert!(result.verified);
    }

    /// Legacy key at the top level: trust the cache fully, no upstream linking required.
    #[test]
    fn legacy_key_skips_upstream() {
        let mut facts = Facts::new();
        // No FOD. No A-side signing. Just a cache claim at B.
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into()); // A's resolution is "claimed" but A is unsigned
        facts.add_claim(R_B_1, K_CACHE, make_output_map(&[(OUT, HB)]));

        // Trust the legacy cache key OR a stricter normal model.
        let tm = TrustModel::Threshold(
            1,
            vec![
                TrustModel::KeyLegacy(K_CACHE),
                TrustModel::Key(K1), // not satisfied here
            ],
        );
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(
            result.verified,
            "legacy cache key bypasses upstream verification"
        );
        // Evidence is only at B; A was not visited because the legacy thread ends here.
        assert!(!result.evidence.contains_key(&A));
    }

    /// `KeyLegacy` is rejected if it appears outside a top-level Threshold(1, ...).
    #[test]
    fn legacy_rejected_inside_nested_model() {
        // Threshold of 2 with a legacy child — not allowed.
        let tm =
            TrustModel::Threshold(2, vec![TrustModel::KeyLegacy(K_CACHE), TrustModel::Key(K1)]);
        let facts = Facts::new();
        assert!(Verifier::new(&facts, &tm).is_err());

        // Legacy nested inside an inner threshold — also not allowed.
        let tm = TrustModel::Threshold(
            1,
            vec![TrustModel::Threshold(
                1,
                vec![TrustModel::KeyLegacy(K_CACHE)],
            )],
        );
        assert!(Verifier::new(&facts, &tm).is_err());
    }

    /// Target with no signed claims fails — the trust model must be satisfied AT the root,
    /// and a vacuous evidence map doesn't count.
    #[test]
    fn target_without_signed_claims_fails() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        // B's rdrv exists but no claim is signed for it.
        facts.add_rdrv(R_B_1, B, [((F1, OUT), HF)].into());

        let tm = threshold(1, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(!result.verified);
    }

    /// Target IS a FOD: trivially verified without any signed evidence.
    #[test]
    fn fod_target_is_trivially_verified() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(F1, make_subset(&[(OUT, HF)]));
        assert!(result.verified);
    }
}
