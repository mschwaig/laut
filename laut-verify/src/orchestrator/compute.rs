//! Resolved-input-hash computation and the signature-fetch/verify plumbing
//! that feeds [`super::resolutions::collect_resolutions`].

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use laut_sign::{constructive_trace, store_path};

use crate::backend::Backend;
use crate::signature_verify;
use crate::types::{TrustlesslyResolvedDerivation, UnresolvedDerivation};

use super::{Error, Orchestrator};

impl<B: Backend> Orchestrator<B> {
    /// Returns `(ct_input_hash, aterm_bytes_string)` for `udrv` under the given
    /// resolution. `combo` is empty for FODs / leaves.
    pub(super) fn compute_resolved(
        &self,
        udrv: &UnresolvedDerivation,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) -> Result<(String, String), Error> {
        let str_resolutions = build_string_resolutions(combo);
        let aterm = self.backend.derivation_aterm(&udrv.drv_path)?;
        let (resolved_drv_path, aterm_bytes) = constructive_trace::compute_resolved_input_hash(
            &udrv.name,
            aterm.as_bytes(),
            &str_resolutions,
        )
        .map_err(|e| Error::ConstructiveTrace(format!("{}", e)))?;
        let ct_input_hash = store_path::extract_store_hash(&resolved_drv_path)?;
        Ok((ct_input_hash, aterm_bytes))
    }

    /// Same as `compute_resolved` but returns just the resolved drv path
    /// (used to populate `TrustlesslyResolvedDerivation.drv_path`).
    pub(super) fn compute_resolved_drv_path(
        &self,
        udrv: &UnresolvedDerivation,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) -> Result<String, Error> {
        let str_resolutions = build_string_resolutions(combo);
        let aterm = self.backend.derivation_aterm(&udrv.drv_path)?;
        let (resolved_drv_path, _aterm_bytes) = constructive_trace::compute_resolved_input_hash(
            &udrv.name,
            aterm.as_bytes(),
            &str_resolutions,
        )
        .map_err(|e| Error::ConstructiveTrace(format!("{}", e)))?;
        Ok(resolved_drv_path)
    }

    pub(super) fn fetch_and_verify_signatures(
        &mut self,
        input_hash: &str,
    ) -> Result<Vec<(Value, String)>, Error> {
        if let Some(cached) = self.sig_memo.get(input_hash) {
            return Ok(cached.clone());
        }
        let raw = self.fetch_raw_signatures(input_hash)?;
        let valid = self.verify_signatures(input_hash, &raw)?;
        self.sig_memo.insert(input_hash.to_owned(), valid.clone());
        Ok(valid)
    }

    fn fetch_raw_signatures(&self, input_hash: &str) -> Result<Vec<String>, Error> {
        let mut all = Vec::new();
        for cache_url in &self.cache_urls {
            let body = match self.backend.fetch_signatures(cache_url, input_hash) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(_) => continue,
            };
            let parsed: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(sigs) = parsed.get("signatures").and_then(|v| v.as_array()) {
                for s in sigs {
                    if let Some(s) = s.as_str() {
                        all.push(s.to_owned());
                    }
                }
            }
        }
        Ok(all)
    }

    fn verify_signatures(
        &self,
        input_hash: &str,
        signatures: &[String],
    ) -> Result<Vec<(Value, String)>, Error> {
        let results = signature_verify::verify_resolved_trace_signatures(
            input_hash,
            signatures,
            &self.trusted_keys,
        )?;
        let mut out = Vec::new();
        for (payload_str, kid) in results {
            let payload: Value = match serde_json::from_str(&payload_str) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push((payload, kid));
        }
        Ok(out)
    }
}

/// Flatten a resolution map into the `dep_drv_path -> {output_name -> content_hash}`
/// shape that `constructive_trace::compute_resolved_input_hash` expects.
fn build_string_resolutions(
    combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
) -> HashMap<String, HashMap<String, String>> {
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (dep_drv_path, resolved) in combo {
        let mut outputs: HashMap<String, String> = HashMap::new();
        for (unresolved_output, content_hash) in &resolved.outputs {
            outputs.insert(unresolved_output.output_name.clone(), content_hash.clone());
        }
        out.insert(dep_drv_path.clone(), outputs);
    }
    out
}
