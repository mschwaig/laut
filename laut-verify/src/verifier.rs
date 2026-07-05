//! Trust-model verification for laut.
//!
//! Implements the witness-family semantics from `docs/semantics.md`:
//! verification of a target `(udrv, output_subset)` succeeds iff every
//! dependency path of the target has a *witness family* — a non-empty set of
//! grounded, linked paths of provenance-log claims such that at every position
//! (udrv) along the dependency path,
//!
//!   1. no two paths of the family use the same signer (unit capacity per
//!      (position, key)), and
//!   2. the set of signers the family uses at that position is a *qualified*
//!      set of the trust model's access structure.
//!
//! Equivalently (Menger / max-flow–min-cut, for flat thresholds): the trust
//! model must hold across every *cut* separating the inputs from the target,
//! not merely at every position. Checking positions in isolation would accept
//! configurations where signatures that never link into a common route are
//! counted together; see the `alternating_reinforcement_*` tests.
//!
//! The algorithm is a demand-driven search from the target toward the inputs.
//! The state at a position is a set of *alternative demand multisets*: each
//! multiset lists, per path of a candidate family, the output subset that
//! path's downstream claim requires here. Alternatives arise because family
//! width and upstream routing are chosen per dependency path. At each
//! position, serving one demand multiset means choosing, per demand, a route
//! (an rdrv whose matching claims continue upstream, or a legacy claim that
//! terminates the path) and then an injective, qualified signer assignment —
//! a small bipartite matching, enumerated over signer bitmasks. Realizable
//! choices induce the demand multisets for each dependency position; claims
//! that never link toward the target are never visited.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
    /// Pure monotone predicate over a key set: is `keys` a qualified set of
    /// the access structure this model denotes?
    pub fn satisfied_by(&self, keys: &HashSet<KeyId>) -> bool {
        match self {
            TrustModel::Key(k) | TrustModel::KeyLegacy(k) => keys.contains(k),
            TrustModel::Threshold(t, children) => {
                let count = children.iter().filter(|c| c.satisfied_by(keys)).count();
                count >= *t
            }
        }
    }

    /// Leaf keys in tree order (both `Key` and `KeyLegacy`).
    fn collect_leaf_keys(&self, out: &mut Vec<KeyId>) {
        match self {
            TrustModel::Key(k) | TrustModel::KeyLegacy(k) => out.push(*k),
            TrustModel::Threshold(_, children) => {
                for c in children {
                    c.collect_leaf_keys(out);
                }
            }
        }
    }

    /// Size of the smallest qualified set. Family widths below this can never
    /// satisfy condition 2, so the search skips them.
    fn min_qualified_size(&self) -> usize {
        match self {
            TrustModel::Key(_) | TrustModel::KeyLegacy(_) => 1,
            TrustModel::Threshold(t, children) => {
                let mut sizes: Vec<usize> =
                    children.iter().map(|c| c.min_qualified_size()).collect();
                sizes.sort_unstable();
                sizes.into_iter().take(*t).sum()
            }
        }
    }

    /// Structural well-formedness:
    ///
    /// - Each key appears in at most one leaf. Otherwise a single key could
    ///   satisfy several leaves at once and a threshold would count the same
    ///   signature more than once.
    /// - Every `Threshold(t, children)` has `1 <= t <= children.len()`.
    /// - `KeyLegacy` may only appear as a direct child of a top-level
    ///   `Threshold(1, ...)`. This is what makes the legacy short-circuit
    ///   unambiguous: the user opts in to "trust this signer as-is" via an OR
    ///   at the very root of the model.
    ///
    /// Returns the set of legacy keys.
    pub fn validate(&self) -> Result<HashSet<KeyId>, String> {
        let mut leaf_keys = Vec::new();
        self.collect_leaf_keys(&mut leaf_keys);
        let mut seen = HashSet::new();
        for k in &leaf_keys {
            if !seen.insert(*k) {
                return Err(
                    "a key may appear in at most one leaf of the trust model".into(),
                );
            }
        }
        self.validate_thresholds()?;

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

    fn validate_thresholds(&self) -> Result<(), String> {
        if let TrustModel::Threshold(t, children) = self {
            if *t < 1 || *t > children.len() {
                return Err(format!(
                    "threshold {} out of range 1..={}",
                    t,
                    children.len()
                ));
            }
            for c in children {
                c.validate_thresholds()?;
            }
        }
        Ok(())
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// All input data the verifier reasons about, pre-indexed for the search.
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
    /// as it arrives from the orchestrator; this method groups it by dep_udrv.
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

/// The demands one candidate family places on a position: per path of the
/// family, the output subset its downstream claim requires here. Kept sorted
/// so it can serve as a memo key.
type Demands = Vec<Subset>;

/// How one demand of a multiset is served at a position.
#[derive(Clone, Debug)]
enum RouteOption {
    /// The path continues upstream through claims on this rdrv; `cand` is the
    /// bitmask of (non-legacy) model keys signing a matching claim on it.
    Continue { rdrv: RDrv, cand: u64 },
    /// The path terminates at a legacy-signed claim; `cand` is the bitmask of
    /// legacy keys with a matching claim at this position.
    Terminate { cand: u64 },
}

impl RouteOption {
    fn cand(&self) -> u64 {
        match self {
            RouteOption::Continue { cand, .. } | RouteOption::Terminate { cand } => *cand,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub verified: bool,
    /// Signers usable by witness families at each position, collected during a
    /// successful search. Empty when verification fails.
    pub evidence: HashMap<UDrv, HashSet<KeyId>>,
    /// Positions together with a demand multiset that could not be served by
    /// distinct, qualified signers. Populated during the search; only
    /// meaningful as diagnostics when verification fails.
    pub unservable: Vec<(UDrv, Vec<Subset>)>,
}

/// The verifier holds borrowed references to the facts and trust model plus
/// the memo tables built up during a single call.
pub struct Verifier<'a> {
    facts: &'a Facts,
    trust_model: &'a TrustModel,
    legacy_keys: HashSet<KeyId>,

    /// Model keys in a stable order; the index is the key's bit position in
    /// signer bitmasks. Claims by keys outside the model can never contribute
    /// to a qualified set and are ignored entirely.
    model_keys: Vec<KeyId>,
    key_bit: HashMap<KeyId, usize>,
    /// Smallest possible family width (size of the smallest qualified set).
    min_width: usize,

    /// Memo for `covered`. The default-false-during-recursion idiom prevents
    /// infinite recursion on malformed cyclic inputs.
    covered_memo: HashMap<(UDrv, Vec<Demands>), bool>,
    qualified_memo: HashMap<u64, bool>,

    evidence_acc: HashMap<UDrv, HashSet<KeyId>>,
    unservable_acc: BTreeSet<(UDrv, Demands)>,
}

impl<'a> Verifier<'a> {
    pub fn new(facts: &'a Facts, trust_model: &'a TrustModel) -> Result<Self, String> {
        let legacy_keys = trust_model.validate()?;
        let mut model_keys = Vec::new();
        trust_model.collect_leaf_keys(&mut model_keys);
        if model_keys.len() > 64 {
            return Err(format!(
                "trust model has {} keys; at most 64 are supported",
                model_keys.len()
            ));
        }
        let key_bit = model_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (*k, i))
            .collect();
        let min_width = trust_model.min_qualified_size();
        Ok(Verifier {
            facts,
            trust_model,
            legacy_keys,
            model_keys,
            key_bit,
            min_width,
            covered_memo: HashMap::new(),
            qualified_memo: HashMap::new(),
            evidence_acc: HashMap::new(),
            unservable_acc: BTreeSet::new(),
        })
    }

    /// Verify `(target_udrv, target_subset)` per the witness-family semantics.
    pub fn verify(&mut self, target_udrv: UDrv, target_subset: Subset) -> VerifyResult {
        self.covered_memo.clear();
        self.evidence_acc.clear();
        self.unservable_acc.clear();

        let verified = if let Some(fod_outputs) = self.facts.fods.get(&target_udrv) {
            // A target that is itself an FOD verifies trivially against its
            // known output map; no signed evidence is required.
            target_subset.matches_output_map(fod_outputs)
        } else {
            // Family width is chosen per dependency path; feed every viable
            // width as an alternative demand multiset for the target position.
            let alternatives: Vec<Demands> = (self.min_width..=self.model_keys.len())
                .map(|m| vec![target_subset.clone(); m])
                .collect();
            self.covered(target_udrv, alternatives)
        };

        VerifyResult {
            verified,
            evidence: if verified {
                std::mem::take(&mut self.evidence_acc)
            } else {
                HashMap::new()
            },
            unservable: std::mem::take(&mut self.unservable_acc).into_iter().collect(),
        }
    }

    /// True iff every dependency path from `udrv` can be covered by a witness
    /// family serving one of the `alternatives` demand multisets. Alternatives
    /// exist because families (and hence widths and routes) are chosen per
    /// dependency path; each path commits to one alternative.
    fn covered(&mut self, udrv: UDrv, mut alternatives: Vec<Demands>) -> bool {
        alternatives.sort();
        alternatives.dedup();

        // An empty demand multiset means every path of that family already
        // terminated (at a legacy claim) downstream of here: nothing upstream
        // is required on this dependency path.
        if alternatives.iter().any(|d| d.is_empty()) {
            return true;
        }
        if alternatives.is_empty() {
            return false;
        }

        if let Some(fod_outputs) = self.facts.fods.get(&udrv) {
            return alternatives
                .iter()
                .any(|d| d.iter().all(|s| s.matches_output_map(fod_outputs)));
        }

        let memo_key = (udrv, alternatives.clone());
        if let Some(&cached) = self.covered_memo.get(&memo_key) {
            return cached;
        }
        // Set false before recursing so cycles in malformed input terminate.
        self.covered_memo.insert(memo_key.clone(), false);

        let dep_positions = self.dep_positions(udrv);
        let mut evidence_here: HashSet<KeyId> = HashSet::new();
        let mut successors: HashMap<UDrv, BTreeSet<Demands>> = HashMap::new();
        let mut any_transition = false;

        for demands in &alternatives {
            let transitions = self.realizable_transitions(udrv, demands, &dep_positions, &mut evidence_here);
            if transitions.is_empty() {
                self.unservable_acc.insert((udrv, demands.clone()));
                continue;
            }
            any_transition = true;
            for tr in transitions {
                for (dep_udrv, dep_demands) in tr {
                    successors.entry(dep_udrv).or_default().insert(dep_demands);
                }
            }
        }

        let result = if !any_transition {
            false
        } else {
            // Per-path independence: each dependency position only needs SOME
            // alternative to work for the paths that continue through it.
            dep_positions.iter().all(|dep_udrv| {
                let alts: Vec<Demands> = successors
                    .get(dep_udrv)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();
                self.covered(*dep_udrv, alts)
            })
        };

        if result {
            self.evidence_acc
                .entry(udrv)
                .or_default()
                .extend(evidence_here);
        }
        self.covered_memo.insert(memo_key, result);
        result
    }

    /// The dependency positions of `udrv` (every rdrv of a udrv resolves the
    /// same dependency udrvs; the union is defensive).
    fn dep_positions(&self, udrv: UDrv) -> Vec<UDrv> {
        let mut deps = BTreeSet::new();
        if let Some(rdrvs) = self.facts.udrv_to_rdrvs.get(&udrv) {
            for rdrv in rdrvs {
                if let Some(subsets) = self.facts.rdrv_dep_subsets.get(rdrv) {
                    for (dep_udrv, _) in subsets {
                        deps.insert(*dep_udrv);
                    }
                }
            }
        }
        deps.into_iter().collect()
    }

    /// Enumerate the ways `demands` can be served at `udrv`: per demand a
    /// route (continue through an rdrv, or terminate at a legacy claim) such
    /// that an injective, qualified signer assignment exists. Returns the
    /// distinct demand multisets each realizable choice induces per dependency
    /// position. Signers appearing in a qualified assignment are recorded into
    /// `evidence_out`.
    fn realizable_transitions(
        &mut self,
        udrv: UDrv,
        demands: &Demands,
        dep_positions: &[UDrv],
        evidence_out: &mut HashSet<KeyId>,
    ) -> BTreeSet<BTreeMap<UDrv, Demands>> {
        let mut transitions = BTreeSet::new();
        let Some(rdrvs) = self.facts.udrv_to_rdrvs.get(&udrv) else {
            return transitions;
        };

        // Route options per demand.
        let mut options: Vec<Vec<RouteOption>> = Vec::with_capacity(demands.len());
        for subset in demands {
            let mut opts = Vec::new();
            let mut legacy_cand = 0u64;
            for &rdrv in rdrvs {
                let Some(claims) = self.facts.rdrv_claims.get(&rdrv) else {
                    continue;
                };
                let mut cand = 0u64;
                for claim in claims {
                    if !subset.matches_output_map(&claim.output_map) {
                        continue;
                    }
                    // Signers outside the model can never contribute to a
                    // qualified set; ignore their claims.
                    let Some(&bit) = self.key_bit.get(&claim.signer) else {
                        continue;
                    };
                    if self.legacy_keys.contains(&claim.signer) {
                        legacy_cand |= 1 << bit;
                    } else {
                        cand |= 1 << bit;
                    }
                }
                if cand != 0 {
                    opts.push(RouteOption::Continue { rdrv, cand });
                }
            }
            if legacy_cand != 0 {
                opts.push(RouteOption::Terminate { cand: legacy_cand });
            }
            if opts.is_empty() {
                // Some demand cannot be served at all: no transition exists.
                return transitions;
            }
            options.push(opts);
        }

        // Enumerate route vectors (choice of option per demand) depth-first.
        let mut chosen: Vec<usize> = Vec::with_capacity(demands.len());
        self.enumerate_routes(
            &options,
            &mut chosen,
            dep_positions,
            evidence_out,
            &mut transitions,
        );
        transitions
    }

    fn enumerate_routes(
        &mut self,
        options: &[Vec<RouteOption>],
        chosen: &mut Vec<usize>,
        dep_positions: &[UDrv],
        evidence_out: &mut HashSet<KeyId>,
        transitions: &mut BTreeSet<BTreeMap<UDrv, Demands>>,
    ) {
        if chosen.len() == options.len() {
            let route: Vec<&RouteOption> = chosen
                .iter()
                .zip(options)
                .map(|(&i, opts)| &opts[i])
                .collect();

            // Injective signer assignment: track the set of achievable signer
            // bitmasks across demands (condition 1), then check any of them is
            // qualified (condition 2).
            let mut masks: HashSet<u64> = HashSet::new();
            masks.insert(0);
            for opt in &route {
                let cand = opt.cand();
                let mut next = HashSet::new();
                for &mask in &masks {
                    let mut free = cand & !mask;
                    while free != 0 {
                        let bit = free & free.wrapping_neg();
                        next.insert(mask | bit);
                        free &= free - 1;
                    }
                }
                if next.is_empty() {
                    // No injective assignment for this route vector.
                    return;
                }
                masks = next;
            }

            let mut qualified_union = 0u64;
            for &mask in &masks {
                if self.mask_qualified(mask) {
                    qualified_union |= mask;
                }
            }
            if qualified_union == 0 {
                return;
            }
            let mut bits = qualified_union;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                evidence_out.insert(self.model_keys[bit]);
                bits &= bits - 1;
            }

            // Demands induced per dependency position: each continuing rdrv
            // contributes its resolution subset at every dep it resolves;
            // terminated paths contribute nothing.
            let mut tr: BTreeMap<UDrv, Demands> = dep_positions
                .iter()
                .map(|&d| (d, Vec::new()))
                .collect();
            for opt in &route {
                if let RouteOption::Continue { rdrv, .. } = opt {
                    if let Some(subsets) = self.facts.rdrv_dep_subsets.get(rdrv) {
                        for (dep_udrv, subset) in subsets {
                            tr.entry(*dep_udrv).or_default().push(subset.clone());
                        }
                    }
                }
            }
            for d in tr.values_mut() {
                d.sort();
            }
            transitions.insert(tr);
            return;
        }

        for i in 0..options[chosen.len()].len() {
            chosen.push(i);
            self.enumerate_routes(options, chosen, dep_positions, evidence_out, transitions);
            chosen.pop();
        }
    }

    fn mask_qualified(&mut self, mask: u64) -> bool {
        if let Some(&q) = self.qualified_memo.get(&mask) {
            return q;
        }
        let mut keys = HashSet::new();
        let mut bits = mask;
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            keys.insert(self.model_keys[bit]);
            bits &= bits - 1;
        }
        let q = self.trust_model.satisfied_by(&keys);
        self.qualified_memo.insert(mask, q);
        q
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

    fn unservable_at(result: &VerifyResult, udrv: UDrv) -> bool {
        result.unservable.iter().any(|(u, _)| *u == udrv)
    }

    // Distinct IDs for tests. We don't go through the interner so we can keep tests focused
    // on verifier behaviour.
    const F1: UDrv = UDrv(1);
    const A: UDrv = UDrv(2);
    const B: UDrv = UDrv(3);
    const C: UDrv = UDrv(4);

    const R_A_1: RDrv = RDrv(101);
    const R_A_2: RDrv = RDrv(102);
    const R_A_3: RDrv = RDrv(103);
    const R_B_1: RDrv = RDrv(104);
    const R_B_2: RDrv = RDrv(105);
    const R_B_3: RDrv = RDrv(106);
    const R_C_1: RDrv = RDrv(107);
    const R_C_2: RDrv = RDrv(108);

    const OUT: OutputName = OutputName(200);
    const DEV: OutputName = OutputName(201);

    const HF: ContentHash = ContentHash(300);
    const HA: ContentHash = ContentHash(301);
    const HA2: ContentHash = ContentHash(302);
    const HA3: ContentHash = ContentHash(303);
    const HB: ContentHash = ContentHash(304);
    const HB2: ContentHash = ContentHash(305);
    const HC: ContentHash = ContentHash(306);
    const HDEV1: ContentHash = ContentHash(307);
    const HDEV2: ContentHash = ContentHash(308);

    const K1: KeyId = KeyId(400);
    const K2: KeyId = KeyId(401);
    const K3: KeyId = KeyId(402);
    const K_CACHE: KeyId = KeyId(403);

    /// Linear chain FOD -> A -> B with both keys signing every step, agreeing.
    /// Threshold(2) must verify: a width-2 family exists at every position.
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
    /// but B's rdrv resolves A to HA. Both B-demands need HA at A, which only k1 signed;
    /// two paths cannot both use k1 at A. Threshold(2) fails.
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
        assert!(unservable_at(&result, A));
    }

    /// The convergence case: k1 and k2 disagree on A but each signs a B-rdrv that uses
    /// their own A. Both rdrvs at B produce the same HB. The two grounded paths are
    /// signer-disjoint at every position; threshold(2) verifies.
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

    /// Cross-linking is admitted: k1 signs A->HA and B(A=HA2)->HB; k2 signs A->HA2 and
    /// B(A=HA)->HB. Neither key has a single-signer chain, but two signer-disjoint
    /// grounded paths exist (paths may change signers between positions). Entries are
    /// statements about bitwise input/output relations, so they compose across builders.
    #[test]
    fn crosswise_linking_accepted() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_A_2, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_2, K2, make_output_map(&[(OUT, HA2)]));
        // B built against k2's A, signed by k1.
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA2)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        // B built against k1's A, signed by k2.
        facts.add_rdrv(R_B_2, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_2, K2, make_output_map(&[(OUT, HB)]));

        let tm = threshold(2, &[K1, K2]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(result.verified);
    }

    /// The alternating-reinforcement counterexample from docs/semantics.md: k1 and k2
    /// build divergent chains converging at C; k3 co-signs a1, b2, and c-from-b1.
    /// Every position sees all three signers (the old per-position semantics accepted
    /// this), but the cut {k1@b1, k2@a2} has size 2: only 2 disjoint paths exist.
    #[test]
    fn alternating_reinforcement_rejected_at_three() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        // A: k1+k3 sign a1, k2 signs a2.
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_claim(R_A_1, K3, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_A_2, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_2, K2, make_output_map(&[(OUT, HA2)]));
        // B: k1 signs b1 (from a1); k2+k3 sign b2 (from a2).
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_rdrv(R_B_2, B, [((A, OUT), HA2)].into());
        facts.add_claim(R_B_2, K2, make_output_map(&[(OUT, HB2)]));
        facts.add_claim(R_B_2, K3, make_output_map(&[(OUT, HB2)]));
        // C: k1+k3 sign c from b1; k2 signs c from b2 (converges).
        facts.add_rdrv(R_C_1, C, [((B, OUT), HB)].into());
        facts.add_claim(R_C_1, K1, make_output_map(&[(OUT, HC)]));
        facts.add_claim(R_C_1, K3, make_output_map(&[(OUT, HC)]));
        facts.add_rdrv(R_C_2, C, [((B, OUT), HB2)].into());
        facts.add_claim(R_C_2, K2, make_output_map(&[(OUT, HC)]));

        let tm3 = threshold(3, &[K1, K2, K3]);
        let mut v = Verifier::new(&facts, &tm3).unwrap();
        let result = v.verify(C, make_subset(&[(OUT, HC)]));
        assert!(
            !result.verified,
            "only 2 signer-disjoint grounded paths exist; 3-of-3 must fail"
        );

        // The same evidence carries width 2: 2-of-3 verifies.
        let tm2 = threshold(2, &[K1, K2, K3]);
        let mut v = Verifier::new(&facts, &tm2).unwrap();
        let result = v.verify(C, make_subset(&[(OUT, HC)]));
        assert!(result.verified, "two disjoint paths exist; 2-of-3 verifies");
    }

    /// Hall-condition failure: three divergent routes at A, demanded by three B-rdrvs.
    /// Routes a1 and a2 are both signed only by k1; a3 by k2 and k3. Per-route counts
    /// and the per-position distinct-signer count (3) both look sufficient, but a1 and
    /// a2 jointly need two distinct signers and only k1 covers them.
    #[test]
    fn hall_condition_failure_detected() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_A_2, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_2, K1, make_output_map(&[(OUT, HA2)]));
        facts.add_rdrv(R_A_3, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_3, K2, make_output_map(&[(OUT, HA3)]));
        facts.add_claim(R_A_3, K3, make_output_map(&[(OUT, HA3)]));

        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_rdrv(R_B_2, B, [((A, OUT), HA2)].into());
        facts.add_claim(R_B_2, K2, make_output_map(&[(OUT, HB)]));
        facts.add_rdrv(R_B_3, B, [((A, OUT), HA3)].into());
        facts.add_claim(R_B_3, K3, make_output_map(&[(OUT, HB)]));

        let tm = threshold(3, &[K1, K2, K3]);
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(!result.verified);
        assert!(unservable_at(&result, A));
    }

    /// "No double counting at a position": k1 signs both divergent A claims, k2 signs
    /// only at B. Any width-2 family needs two distinct signers at A; only k1 signs
    /// there. Threshold(2) fails.
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
        assert!(unservable_at(&result, A));
    }

    /// Threshold(1) — any single signer suffices, and the single grounded path may
    /// change signers between positions.
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

    /// A family may switch OR-branches between positions: the cache backing the
    /// second family slot is cache_a at one position and cache_b at the next.
    #[test]
    fn nested_or_switches_branch_across_positions() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        // A signed by self (K1) and cache_b (K3).
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_claim(R_A_1, K3, make_output_map(&[(OUT, HA)]));
        // B signed by self (K1) and cache_a (K2).
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K1, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));

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

    /// Mixed-arity OR funneling is rejected: with threshold(1, [k1, threshold(2,
    /// [k2, k3])]), a graph where B is covered only by {k2, k3} (width 2) and A only
    /// by k1 (width 1) does not verify — the two-signer corroboration at B would
    /// funnel through k1's single signature at A. Family width is uniform along a
    /// dependency path.
    #[test]
    fn mixed_arity_or_funneling_rejected() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        facts.add_rdrv(R_B_1, B, [((A, OUT), HA)].into());
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K3, make_output_map(&[(OUT, HB)]));

        let tm = TrustModel::Threshold(
            1,
            vec![
                TrustModel::Key(K1),
                TrustModel::Threshold(2, vec![TrustModel::Key(K2), TrustModel::Key(K3)]),
            ],
        );
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(B, make_subset(&[(OUT, HB)]));
        assert!(!result.verified);
    }

    /// Family width is chosen per dependency path: the path through A verifies at
    /// width 1 (via k1), the path through B at width 2 (via {k2, k3}). Different
    /// paths may use different widths and OR-branches.
    #[test]
    fn family_width_chosen_per_dependency_path() {
        let mut facts = Facts::new();
        facts.add_fod(F1, make_output_map(&[(OUT, HF)]));
        // A covered only by k1.
        facts.add_rdrv(R_A_1, A, [((F1, OUT), HF)].into());
        facts.add_claim(R_A_1, K1, make_output_map(&[(OUT, HA)]));
        // B covered only by k2+k3.
        facts.add_rdrv(R_B_1, B, [((F1, OUT), HF)].into());
        facts.add_claim(R_B_1, K2, make_output_map(&[(OUT, HB)]));
        facts.add_claim(R_B_1, K3, make_output_map(&[(OUT, HB)]));
        // C depends on both; everyone signs it.
        facts.add_rdrv(R_C_1, C, [((A, OUT), HA), ((B, OUT), HB)].into());
        facts.add_claim(R_C_1, K1, make_output_map(&[(OUT, HC)]));
        facts.add_claim(R_C_1, K2, make_output_map(&[(OUT, HC)]));
        facts.add_claim(R_C_1, K3, make_output_map(&[(OUT, HC)]));

        let tm = TrustModel::Threshold(
            1,
            vec![
                TrustModel::Key(K1),
                TrustModel::Threshold(2, vec![TrustModel::Key(K2), TrustModel::Key(K3)]),
            ],
        );
        let mut v = Verifier::new(&facts, &tm).unwrap();
        let result = v.verify(C, make_subset(&[(OUT, HC)]));
        assert!(result.verified);
    }

    /// Multi-output udrv. Builders disagree on $dev but agree on $out. The verification
    /// target asks for $out only, and both builders' claims serve it.
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
        // Only k1's A-signing matches the (out=HA, dev=HDEV1) requirement; a width-2
        // family cannot find two distinct signers at A.
        assert!(!result.verified);
        assert!(unservable_at(&result, A));
    }

    /// DAG with sharing: FOD feeds into both A and a sibling B that converge at C.
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
        // Evidence is only at B; A was not visited because the legacy path ends here.
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

    /// A key may appear in at most one leaf of the trust model. Duplicates would let
    /// a single signature light several leaves at once (self-corroboration).
    #[test]
    fn duplicate_key_in_model_rejected() {
        let facts = Facts::new();

        let tm = TrustModel::Threshold(2, vec![TrustModel::Key(K1), TrustModel::Key(K1)]);
        assert!(Verifier::new(&facts, &tm).is_err());

        // Duplicate across nesting levels is also rejected.
        let tm = TrustModel::Threshold(
            2,
            vec![
                TrustModel::Key(K1),
                TrustModel::Threshold(1, vec![TrustModel::Key(K1), TrustModel::Key(K2)]),
            ],
        );
        assert!(Verifier::new(&facts, &tm).is_err());
    }

    /// Threshold arities are validated: t must satisfy 1 <= t <= n.
    #[test]
    fn threshold_bounds_validated() {
        let facts = Facts::new();

        let tm = TrustModel::Threshold(0, vec![TrustModel::Key(K1)]);
        assert!(Verifier::new(&facts, &tm).is_err());

        let tm = TrustModel::Threshold(3, vec![TrustModel::Key(K1), TrustModel::Key(K2)]);
        assert!(Verifier::new(&facts, &tm).is_err());
    }

    /// Target with no signed claims fails — no witness family exists at the root.
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
        assert!(unservable_at(&result, B));
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
