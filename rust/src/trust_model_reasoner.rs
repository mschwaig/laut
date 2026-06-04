//! Python-facing wrapper around `verifier::Verifier`.
//!
//! The Python verification pipeline calls this incrementally as it walks the unresolved
//! dependency tree, fetches signatures, and feeds in everything the verifier needs.
//! Then it calls `compute_result()` to run the actual verification.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::string_interner::{ContentHash, KeyId, OutputName, StringInterner, UDrv};
use crate::verifier::{Facts, Subset, TrustModel, VerifyResult, Verifier};

#[pyclass(unsendable)]
pub struct TrustModelReasoner {
    interner: StringInterner,
    facts: Facts,
    trust_model: TrustModel,
    expected_root: UDrv,
}

#[pymethods]
impl TrustModelReasoner {
    #[new]
    fn new(trusted_keys: Vec<String>, threshold: usize, expected_root: String) -> PyResult<Self> {
        if trusted_keys.is_empty() {
            return Err(PyValueError::new_err(
                "No trusted keys configured. Please specify at least one trusted key using --trusted-key",
            ));
        }
        if threshold == 0 {
            return Err(PyValueError::new_err("Threshold must be greater than 0"));
        }
        if threshold > trusted_keys.len() {
            return Err(PyValueError::new_err(format!(
                "Threshold ({}) cannot exceed number of trusted keys ({})",
                threshold,
                trusted_keys.len()
            )));
        }

        let mut interner = StringInterner::new();
        let key_ids: Vec<KeyId> = trusted_keys.iter().map(|k| interner.key(k)).collect();
        let trust_model = TrustModel::Threshold(
            threshold,
            key_ids.into_iter().map(TrustModel::Key).collect(),
        );
        // Validate eagerly so configuration errors surface at constructor time.
        trust_model
            .validate()
            .map_err(|e| PyValueError::new_err(e))?;

        let expected_root = interner.udrv(&expected_root);

        Ok(TrustModelReasoner {
            interner,
            facts: Facts::new(),
            trust_model,
            expected_root,
        })
    }

    fn add_fod(&mut self, fod_drv_path: &str, fod_out_hash: &str) -> PyResult<()> {
        let udrv = self.interner.udrv(fod_drv_path);
        let out = self.interner.output_name("out");
        let hash = self.interner.content_hash(fod_out_hash);
        let mut outputs = HashMap::new();
        outputs.insert(out, hash);
        self.facts.add_fod(udrv, outputs);
        Ok(())
    }

    /// `depends_on` and `outputs` arrive from Python as `"drv_path$output_name"` strings.
    /// We store the udrv's outputs as a side effect of interning them; deps are recorded
    /// per-rdrv via `add_resolved_derivation`, so this method only needs to ensure the
    /// udrv itself is interned and known.
    fn add_unresolved_derivation(
        &mut self,
        udrv_drv_path: &str,
        _depends_on: Vec<String>,
        _outputs: Vec<String>,
    ) -> PyResult<()> {
        let _ = self.interner.udrv(udrv_drv_path);
        Ok(())
    }

    fn add_resolved_derivation(
        &mut self,
        resolves_udrv: &str,
        with_rdrv: &str,
        resolving_x_with_y: HashMap<String, String>,
    ) -> PyResult<()> {
        let udrv = self.interner.udrv(resolves_udrv);
        let rdrv = self.interner.rdrv(with_rdrv);

        let mut dep_resolutions: HashMap<(UDrv, OutputName), ContentHash> = HashMap::new();
        for (output_ref, content_hash_str) in resolving_x_with_y {
            let (dep_udrv, output_name) = parse_output_ref(&mut self.interner, &output_ref)?;
            let content_hash = self.interner.content_hash(&content_hash_str);
            dep_resolutions.insert((dep_udrv, output_name), content_hash);
        }
        self.facts.add_rdrv(rdrv, udrv, dep_resolutions);
        Ok(())
    }

    fn add_build_output_claim(
        &mut self,
        from_resolved: &str,
        building_x_into_y_says_z: HashMap<String, String>,
        according_to: &str,
    ) -> PyResult<()> {
        let rdrv = self.interner.rdrv(from_resolved);
        let signer = self.interner.key(according_to);

        // Every output_ref in this map should belong to the same udrv (the one this
        // rdrv resolves). We don't enforce that here; if Python sends inconsistent
        // data, the resulting claim simply won't match any subset downstream.
        let mut output_map: HashMap<OutputName, ContentHash> = HashMap::new();
        for (output_ref, content_hash_str) in building_x_into_y_says_z {
            let (_udrv, output_name) = parse_output_ref(&mut self.interner, &output_ref)?;
            let content_hash = self.interner.content_hash(&content_hash_str);
            output_map.insert(output_name, content_hash);
        }
        self.facts.add_claim(rdrv, signer, output_map);
        Ok(())
    }

    /// Try to verify every plausible output map for the expected root.
    /// Returns a list of debug strings, one per verified output map. The Python caller
    /// only checks emptiness today, but the strings are useful in logs.
    ///
    /// When no candidate verifies, prints a per-candidate diagnostic to stderr listing
    /// the positions whose accumulated evidence didn't satisfy the trust model. This
    /// is what you want to read when verification fails in the field: it tells you
    /// which build steps are missing signatures vs. which are signed but disagree.
    fn compute_result(&mut self) -> PyResult<Vec<String>> {
        let candidates = collect_candidate_output_maps(&self.facts, self.expected_root);

        if candidates.is_empty() {
            eprintln!(
                "[laut verify] no signed claims found for root udrv {}",
                self.interner.udrv_str(self.expected_root).unwrap_or("?")
            );
            return Ok(Vec::new());
        }

        let mut verifier = Verifier::new(&self.facts, &self.trust_model)
            .map_err(|e| PyValueError::new_err(e))?;

        let mut verified = Vec::new();
        let mut successes: Vec<(Subset, VerifyResult)> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        for subset in candidates {
            let result = verifier.verify(self.expected_root, subset.clone());
            if result.verified {
                verified.push(self.format_subset(&subset));
                successes.push((subset, result));
            } else {
                failures.push(self.format_verification_failure(&subset, &result));
            }
        }

        if !successes.is_empty() {
            eprintln!(
                "[laut verify] verification SUCCEEDED for root {}",
                self.interner.udrv_str(self.expected_root).unwrap_or("?")
            );
            for (subset, result) in &successes {
                self.print_success_summary(subset, result);
            }
        } else {
            eprintln!(
                "[laut verify] verification FAILED — all {} candidate output map(s) at the root rejected:",
                failures.len()
            );
            for failure in &failures {
                eprint!("{}", failure);
            }
        }

        Ok(verified)
    }
}

impl TrustModelReasoner {
    /// Describe what verified for a particular candidate output_map.
    /// Lists each verified output and its content hash, then summarises the bundle:
    /// number of build-step positions whose evidence satisfied the trust model, and
    /// the union of distinct signing keys observed across the bundle.
    fn print_success_summary(&self, subset: &Subset, result: &VerifyResult) {
        eprintln!("  verified outputs:");
        for (out, ch) in subset.entries() {
            eprintln!(
                "    {} = {}",
                self.interner.output_name_str(*out).unwrap_or("?"),
                self.interner.content_hash_str(*ch).unwrap_or("?")
            );
        }

        let position_count = result.evidence.len();
        let mut all_signers: HashSet<KeyId> = HashSet::new();
        for keys in result.evidence.values() {
            all_signers.extend(keys.iter().copied());
        }
        let mut signer_names: Vec<&str> = all_signers
            .iter()
            .map(|k| self.interner.key_str(*k).unwrap_or("?"))
            .collect();
        signer_names.sort();

        eprintln!(
            "  trust model satisfied at {} build-step position(s)",
            position_count
        );
        eprintln!("  signers contributing to the bundle: {{{}}}", signer_names.join(", "));
    }

    /// Describe why a particular candidate output_map didn't verify. Lists every
    /// position whose evidence set fails the trust model, and includes that set so
    /// the operator can see whether the position has zero, one, or "wrong" keys.
    fn format_verification_failure(
        &self,
        subset: &Subset,
        result: &crate::verifier::VerifyResult,
    ) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "  candidate: {}", self.format_subset(subset));

        if !result.reachable.contains(&(self.expected_root, subset.clone())) {
            let _ = writeln!(out, "    no supporting threads to this candidate");
            return out;
        }

        let mut bad_positions: Vec<_> = result
            .evidence
            .iter()
            .filter(|(_, keys)| !self.trust_model.satisfied_by(keys))
            .collect();
        bad_positions.sort_by_key(|(u, _)| u.0);

        if !result.evidence.contains_key(&self.expected_root)
            && !self.facts.fods.contains_key(&self.expected_root)
        {
            let _ = writeln!(
                out,
                "    root position has no signed claims (no rdrv-claim at the root matched the candidate output map)"
            );
        }

        for (udrv, keys) in bad_positions {
            let key_names: Vec<&str> = keys
                .iter()
                .map(|k| self.interner.key_str(*k).unwrap_or("?"))
                .collect();
            let _ = writeln!(
                out,
                "    position {} insufficient: keys={{{}}}",
                self.interner.udrv_str(*udrv).unwrap_or("?"),
                key_names.join(", ")
            );
        }
        out
    }

    fn format_subset(&self, subset: &Subset) -> String {
        let parts: Vec<String> = subset
            .entries()
            .iter()
            .map(|(out, ch)| {
                format!(
                    "{}={}",
                    self.interner.output_name_str(*out).unwrap_or("?"),
                    self.interner.content_hash_str(*ch).unwrap_or("?")
                )
            })
            .collect();
        format!(
            "{}: {}",
            self.interner.udrv_str(self.expected_root).unwrap_or("?"),
            parts.join(", ")
        )
    }
}

/// Parse a "drv_path$output_name" reference into its components, interning both halves.
fn parse_output_ref(
    interner: &mut StringInterner,
    s: &str,
) -> PyResult<(UDrv, OutputName)> {
    // Split on the last '$' since drv paths shouldn't contain '$' but we want to be safe.
    let idx = s.rfind('$').ok_or_else(|| {
        PyValueError::new_err(format!(
            "Output reference '{}' missing '$' separator between drv path and output name",
            s
        ))
    })?;
    let (drv_path, output_with_dollar) = s.split_at(idx);
    let output_name_str = &output_with_dollar[1..]; // skip '$'
    if drv_path.is_empty() || output_name_str.is_empty() {
        return Err(PyValueError::new_err(format!(
            "Malformed output reference '{}'",
            s
        )));
    }
    let udrv = interner.udrv(drv_path);
    let output_name = interner.output_name(output_name_str);
    Ok((udrv, output_name))
}

/// Collect every output map that some signed rdrv-claim claims for the root udrv.
/// These become the candidate verification targets.
fn collect_candidate_output_maps(facts: &Facts, root_udrv: UDrv) -> Vec<Subset> {
    // FOD root case: just the FOD's own outputs.
    if let Some(outputs) = facts.fods.get(&root_udrv) {
        return vec![Subset::from_pairs(outputs.iter().map(|(o, c)| (*o, *c)))];
    }

    let Some(rdrvs) = facts.udrv_to_rdrvs.get(&root_udrv) else {
        return Vec::new();
    };

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for rdrv in rdrvs {
        let Some(claims) = facts.rdrv_claims.get(rdrv) else {
            continue;
        };
        for claim in claims {
            let subset = Subset::from_pairs(claim.output_map.iter().map(|(o, c)| (*o, *c)));
            if seen.insert(subset.clone()) {
                out.push(subset);
            }
        }
    }
    out
}
