//! Formatting helpers for success/failure summaries and the function that
//! gathers candidate root output maps from the [`Facts`] table.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::string_interner::{KeyId, UDrv};
use crate::verifier::{Facts, Subset, VerifyResult};

use super::Orchestrator;

impl<B: Backend> Orchestrator<B> {
    pub(super) fn format_subset(&self, subset: &Subset) -> String {
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

    pub(super) fn print_success_summary(&self, subset: &Subset, result: &VerifyResult) {
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
        eprintln!(
            "  signers contributing to the bundle: {{{}}}",
            signer_names.join(", ")
        );
    }

    pub(super) fn format_verification_failure(
        &self,
        subset: &Subset,
        result: &VerifyResult,
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
}

/// Collect every output map that some signed rdrv-claim claims for the root
/// udrv. These become the candidate verification targets.
pub(super) fn collect_candidate_output_maps(facts: &Facts, root_udrv: UDrv) -> Vec<Subset> {
    if let Some(outputs) = facts.fods.get(&root_udrv) {
        return vec![Subset::from_pairs(outputs.iter().map(|(o, c)| (*o, *c)))];
    }
    let Some(rdrvs) = facts.udrv_to_rdrvs.get(&root_udrv) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
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
