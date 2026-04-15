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

use std::collections::{HashMap, HashSet};
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use crate::string_interner::{StringInterner, UDrv, UDrvOutput, RDrv, ContentHash, KeyId};

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

#[derive(Default)]
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
type VerifiedOutputs = HashMap<UDrvOutput, HashSet<ContentHash>>;

// =============================================================================
// The verifier
// =============================================================================

struct Verifier<'a> {
    facts: &'a Facts,
    trust_model: &'a TrustModel,
    interner: &'a StringInterner,
    memo: VerifiedOutputs,
}

impl<'a> Verifier<'a> {
    fn new(facts: &'a Facts, trust_model: &'a TrustModel, interner: &'a StringInterner) -> Self {
        Verifier {
            facts,
            trust_model,
            interner,
            memo: HashMap::new(),
        }
    }

    /// Verify a single UDrvOutput. Returns the set of content hashes
    /// that are verified for this output under the trust model.
    fn verify(&mut self, output: UDrvOutput) -> HashSet<ContentHash> {
        // Step 1: memo lookup
        if let Some(cached) = self.memo.get(&output) {
            return cached.clone();
        }

        // Insert empty set BEFORE recursing to handle cycles gracefully.
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
        let mut evidence: HashMap<ContentHash, HashSet<KeyId>> = HashMap::new();

        for rdrv in &rdrvs {
            // Step 3a: check ALL dependency resolutions
            let dep_resolutions = self
                .facts
                .rdrv_dep_resolutions
                .get(rdrv)
                .cloned()
                .unwrap_or_default();

            let mut failed_dep = None;
            let all_deps_ok = dep_resolutions.iter().all(|(dep_out, dep_ch)| {
                let verified_hashes = self.verify(*dep_out);
                let ok = verified_hashes.contains(dep_ch);
                if !ok {
                    failed_dep = Some((*dep_out, *dep_ch, verified_hashes.clone()));
                }
                ok
            });

            if !all_deps_ok {
                if let Some((dep_out, expected_ch, actual_hashes)) = failed_dep {
                    if let (Some(dep_str), Some(expected_str)) =
                        (self.interner.udrv_output_str(dep_out), self.interner.content_hash_str(expected_ch)) {
                        eprintln!("[RUST DEBUG] Dep failed: {} expected {} but got {} verified hashes",
                            dep_str, expected_str, actual_hashes.len());
                    }
                }
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
}

// =============================================================================
// Python bindings
// =============================================================================

#[pyclass]
pub struct TrustModelReasoner {
    interner: StringInterner,
    facts: Facts,
    trust_model: TrustModel,
    expected_root: UDrv,
}

#[pymethods]
impl TrustModelReasoner {
    #[new]
    fn new(trusted_key_names: Vec<String>, threshold: usize, expected_root: &str) -> PyResult<Self> {
        let mut interner = StringInterner::new();

        // Build trust model from trusted keys
        let key_ids: Vec<KeyId> = trusted_key_names
            .iter()
            .map(|name| interner.key_id(name))
            .collect();

        let trust_model = if key_ids.is_empty() {
            return Err(PyValueError::new_err("At least one trusted key is required"));
        } else if key_ids.len() == 1 {
            TrustModel::Key(key_ids[0])
        } else {
            TrustModel::Threshold(
                threshold,
                key_ids.into_iter().map(TrustModel::Key).collect(),
            )
        };

        let expected_root_id = interner.udrv(expected_root);

        Ok(TrustModelReasoner {
            interner,
            facts: Facts::default(),
            trust_model,
            expected_root: expected_root_id,
        })
    }

    /// Add a fixed-output derivation (FOD).
    /// FODs are the leaves of the dependency tree - their content is determined
    /// by their hash, not by how they were built.
    fn add_fod(&mut self, drv_path: &str, output_path: &str) {
        // For FODs, we use the drv_path to create the UDrv and a single "out" output
        let udrv = self.interner.udrv(drv_path);

        // Create the output identifier (drv_path$out)
        let output_id = format!("{}$out", drv_path);
        let udrv_output = self.interner.udrv_output(&output_id);

        // The content hash is the output path itself for FODs
        let content_hash = self.interner.content_hash(output_path);

        // Register the FOD
        self.facts.fods.insert(udrv_output, content_hash);
        self.facts.output_to_udrv.insert(udrv_output, udrv);
        self.facts.udrv_outputs.entry(udrv).or_default().push(udrv_output);
    }

    /// Add an unresolved derivation with its inputs and outputs.
    /// Note: `outputs` should be full output IDs like "/nix/store/abc.drv$out"
    fn add_unresolved_derivation(
        &mut self,
        drv_path: &str,
        inputs: Vec<String>,
        outputs: Vec<String>,
    ) {
        let udrv = self.interner.udrv(drv_path);

        // Register outputs - they are already full output IDs
        for output_id in outputs {
            let udrv_output = self.interner.udrv_output(&output_id);
            self.facts.output_to_udrv.insert(udrv_output, udrv);
            self.facts.udrv_outputs.entry(udrv).or_default().push(udrv_output);
        }

        // Note: inputs are registered when add_resolved_derivation is called,
        // as that's when we know the actual resolution mapping.
        let _ = inputs; // inputs are used implicitly through resolved derivations
    }

    /// Add a resolved derivation that maps an unresolved derivation to a specific
    /// resolution of its dependencies.
    fn add_resolved_derivation(
        &mut self,
        drv_path: &str,
        input_hash: &str,
        resolution: HashMap<String, String>,
    ) {
        let udrv = self.interner.udrv(drv_path);
        let rdrv = self.interner.rdrv(input_hash);

        // Register this rdrv as a resolution of the udrv
        self.facts.udrv_to_rdrvs.entry(udrv).or_default().push(rdrv);

        // Register the dependency resolutions
        let dep_resolutions: Vec<(UDrvOutput, ContentHash)> = resolution
            .iter()
            .map(|(udrv_output_str, content_hash_str)| {
                let udrv_output = self.interner.udrv_output(udrv_output_str);
                let content_hash = self.interner.content_hash(content_hash_str);
                (udrv_output, content_hash)
            })
            .collect();

        self.facts.rdrv_dep_resolutions.insert(rdrv, dep_resolutions);
    }

    /// Add a build output claim from a signature.
    fn add_build_output_claim(
        &mut self,
        rdrv_aterm_ca: &str,
        signature_map: HashMap<String, String>,
        signing_key: &str,
    ) {
        let rdrv = self.interner.rdrv(rdrv_aterm_ca);
        let key = self.interner.key_id(signing_key);

        // Each entry in signature_map is (udrv_output_id -> content_hash)
        for (udrv_output_str, content_hash_str) in signature_map {
            let udrv_output = self.interner.udrv_output(&udrv_output_str);
            let content_hash = self.interner.content_hash(&content_hash_str);

            self.facts
                .rdrv_output_claims
                .entry((rdrv, udrv_output))
                .or_default()
                .push((content_hash, key));
        }
    }

    /// Compute the verification result.
    /// Returns a list of verified content hashes for the expected root's outputs.
    fn compute_result(&self) -> Vec<String> {
        let mut verifier = Verifier::new(&self.facts, &self.trust_model, &self.interner);

        // Debug: print expected root
        if let Some(root_str) = self.interner.udrv_str(self.expected_root) {
            eprintln!("[RUST DEBUG] Expected root: {}", root_str);
        }

        // Get all outputs of the expected root
        let outputs = self.facts.udrv_outputs.get(&self.expected_root)
            .cloned()
            .unwrap_or_default();

        eprintln!("[RUST DEBUG] Expected root has {} outputs", outputs.len());
        for output in &outputs {
            if let Some(out_str) = self.interner.udrv_output_str(*output) {
                eprintln!("[RUST DEBUG]   Output: {}", out_str);
            }
        }

        // Debug: print all registered UDrvs and their outputs
        eprintln!("[RUST DEBUG] Total UDrvs with outputs: {}", self.facts.udrv_outputs.len());
        eprintln!("[RUST DEBUG] Total FODs: {}", self.facts.fods.len());
        eprintln!("[RUST DEBUG] Total RDrv claims: {}", self.facts.rdrv_output_claims.len());
        eprintln!("[RUST DEBUG] Total UDrv->RDrv mappings: {}", self.facts.udrv_to_rdrvs.len());

        // Check if expected_root has any RDrvs mapped
        if let Some(rdrvs) = self.facts.udrv_to_rdrvs.get(&self.expected_root) {
            eprintln!("[RUST DEBUG] Expected root has {} RDrvs", rdrvs.len());
            for rdrv in rdrvs {
                if let Some(rdrv_str) = self.interner.rdrv_str(*rdrv) {
                    eprintln!("[RUST DEBUG]   RDrv: {}", rdrv_str);
                }
                // Check claims for this RDrv
                for output in &outputs {
                    if let Some(claims) = self.facts.rdrv_output_claims.get(&(*rdrv, *output)) {
                        eprintln!("[RUST DEBUG]   Claims for this RDrv+output: {}", claims.len());
                    } else {
                        eprintln!("[RUST DEBUG]   No claims for RDrv+output");
                    }
                }
                // Check dep resolutions
                if let Some(deps) = self.facts.rdrv_dep_resolutions.get(rdrv) {
                    eprintln!("[RUST DEBUG]   Dep resolutions: {}", deps.len());
                    for (dep_out, dep_ch) in deps {
                        if let (Some(out_str), Some(ch_str)) =
                            (self.interner.udrv_output_str(*dep_out), self.interner.content_hash_str(*dep_ch)) {
                            // Check if this dep is a FOD
                            let is_fod = self.facts.fods.contains_key(dep_out);
                            eprintln!("[RUST DEBUG]     Dep: {} -> {} (FOD: {})", out_str, ch_str, is_fod);
                        }
                    }
                } else {
                    eprintln!("[RUST DEBUG]   No dep resolutions");
                }
            }
        } else {
            eprintln!("[RUST DEBUG] Expected root has NO RDrvs mapped!");
        }

        let mut results = Vec::new();

        for output in outputs {
            let verified_hashes = verifier.verify(output);
            eprintln!("[RUST DEBUG] Verified hashes for output: {}", verified_hashes.len());
            for hash in verified_hashes {
                if let Some(hash_str) = self.interner.content_hash_str(hash) {
                    results.push(hash_str.to_string());
                }
            }
        }

        results
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_api_basic() {
        let mut reasoner = TrustModelReasoner::new(
            vec!["key1".to_string(), "key2".to_string()],
            2,
            "/nix/store/abc-foo.drv"
        ).unwrap();

        // Add a FOD
        reasoner.add_fod(
            "/nix/store/fod-source.drv",
            "/nix/store/fod-source-hash"
        );

        // Add an unresolved derivation
        // Note: outputs are full output IDs, not just output names
        reasoner.add_unresolved_derivation(
            "/nix/store/abc-foo.drv",
            vec!["/nix/store/fod-source.drv$out".to_string()],
            vec!["/nix/store/abc-foo.drv$out".to_string()]
        );

        // Add a resolved derivation
        let mut resolution = HashMap::new();
        resolution.insert(
            "/nix/store/fod-source.drv$out".to_string(),
            "/nix/store/fod-source-hash".to_string()
        );
        reasoner.add_resolved_derivation(
            "/nix/store/abc-foo.drv",
            "resolved-hash-123",
            resolution
        );

        // Add build output claims from two keys
        let mut sig_map = HashMap::new();
        sig_map.insert(
            "/nix/store/abc-foo.drv$out".to_string(),
            "/nix/store/abc-foo-output".to_string()
        );
        reasoner.add_build_output_claim("resolved-hash-123", sig_map.clone(), "key1");
        reasoner.add_build_output_claim("resolved-hash-123", sig_map, "key2");

        let results = reasoner.compute_result();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "/nix/store/abc-foo-output");
    }

    #[test]
    fn test_threshold_not_met() {
        let mut reasoner = TrustModelReasoner::new(
            vec!["key1".to_string(), "key2".to_string()],
            2, // require both keys
            "/nix/store/abc-foo.drv"
        ).unwrap();

        // Add a FOD
        reasoner.add_fod(
            "/nix/store/fod-source.drv",
            "/nix/store/fod-source-hash"
        );

        // Add an unresolved derivation
        // Note: outputs are full output IDs, not just output names
        reasoner.add_unresolved_derivation(
            "/nix/store/abc-foo.drv",
            vec!["/nix/store/fod-source.drv$out".to_string()],
            vec!["/nix/store/abc-foo.drv$out".to_string()]
        );

        // Add a resolved derivation
        let mut resolution = HashMap::new();
        resolution.insert(
            "/nix/store/fod-source.drv$out".to_string(),
            "/nix/store/fod-source-hash".to_string()
        );
        reasoner.add_resolved_derivation(
            "/nix/store/abc-foo.drv",
            "resolved-hash-123",
            resolution
        );

        // Only one key signs - threshold not met
        let mut sig_map = HashMap::new();
        sig_map.insert(
            "/nix/store/abc-foo.drv$out".to_string(),
            "/nix/store/abc-foo-output".to_string()
        );
        reasoner.add_build_output_claim("resolved-hash-123", sig_map, "key1");

        let results = reasoner.compute_result();
        assert!(results.is_empty(), "Should not verify with only one key when threshold is 2");
    }
}
