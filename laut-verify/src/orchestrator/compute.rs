//! Resolved-input-hash computation and the signature-fetch/verify plumbing
//! that feeds [`super::resolutions::collect_resolutions`].

use std::collections::{BTreeMap, HashMap};

use nix_compat::store_path::StorePath;
use serde_json::Value;

use laut_sign::{constructive_trace, store_path};

use crate::backend::Backend;
use crate::signature_verify;
use crate::types::{TrustlesslyResolvedDerivation, UnresolvedDerivation};

use super::{Error, Orchestrator, Regime};

impl<B: Backend> Orchestrator<B> {
    /// Returns `(ct_input_hash, aterm_bytes_string)` for `udrv` under the given
    /// resolution. `combo` is empty for FODs / leaves.
    pub(super) fn compute_resolved(
        &mut self,
        udrv: &UnresolvedDerivation,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) -> Result<(String, String), Error> {
        match self.regime {
            Regime::Ca => self.compute_resolved_ca(udrv, combo),
            Regime::Ia => self.compute_resolved_ia(udrv, combo),
        }
    }

    fn compute_resolved_ca(
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

    /// IA branch: substitute IA paths (input drv outputs from combo, this drv's
    /// own outputs from a local closure walk) with their synthetic CA
    /// equivalents, clear inputDrvs, fold the synthetic CA paths into
    /// inputSrcs, and hash the result via the IA constructive-trace routine.
    fn compute_resolved_ia(
        &mut self,
        udrv: &UnresolvedDerivation,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) -> Result<(String, String), Error> {
        let (substitutions, input_sources) = self.build_ia_substitution(udrv, combo)?;

        let aterm = self.backend.derivation_aterm(&udrv.drv_path)?;
        let (resolved_drv_path, aterm_bytes) =
            constructive_trace::compute_resolved_input_hash_ia(
                &udrv.name,
                aterm.as_bytes(),
                input_sources,
                &substitutions,
            )
            .map_err(|e| Error::ConstructiveTrace(format!("{}", e)))?;
        let ct_input_hash = store_path::extract_store_hash(&resolved_drv_path)?;
        Ok((ct_input_hash, aterm_bytes))
    }

    /// Same as `compute_resolved` but returns just the resolved drv path
    /// (used to populate `TrustlesslyResolvedDerivation.drv_path`).
    pub(super) fn compute_resolved_drv_path(
        &mut self,
        udrv: &UnresolvedDerivation,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) -> Result<String, Error> {
        match self.regime {
            Regime::Ca => {
                let str_resolutions = build_string_resolutions(combo);
                let aterm = self.backend.derivation_aterm(&udrv.drv_path)?;
                let (resolved_drv_path, _aterm_bytes) =
                    constructive_trace::compute_resolved_input_hash(
                        &udrv.name,
                        aterm.as_bytes(),
                        &str_resolutions,
                    )
                    .map_err(|e| Error::ConstructiveTrace(format!("{}", e)))?;
                Ok(resolved_drv_path)
            }
            Regime::Ia => {
                let (substitutions, input_sources) = self.build_ia_substitution(udrv, combo)?;
                let aterm = self.backend.derivation_aterm(&udrv.drv_path)?;
                let (resolved_drv_path, _aterm_bytes) =
                    constructive_trace::compute_resolved_input_hash_ia(
                        &udrv.name,
                        aterm.as_bytes(),
                        input_sources,
                        &substitutions,
                    )
                    .map_err(|e| Error::ConstructiveTrace(format!("{}", e)))?;
                Ok(resolved_drv_path)
            }
        }
    }

    /// Build the IA constructive-trace inputs: a flat IA→synthetic-CA path
    /// substitution map (covering input drv outputs from the combo + this
    /// drv's own outputs computed via the shared walker), and the list of
    /// synthetic CA paths to fold into inputSrcs.
    ///
    /// The combo carries dep resolutions as `(udrv_output, content_hash)` where
    /// the content_hash is the dep's synthetic CA path (a TrustlesslyResolvedDerivation
    /// in IA mode resolves outputs to synthetic CA paths, not IA paths). We
    /// look up the dep's original IA path via the recursive DrvJson so the
    /// substitution is keyed correctly on bytes that appear in the ATerm.
    pub(super) fn build_ia_substitution(
        &mut self,
        udrv: &UnresolvedDerivation,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) -> Result<(HashMap<String, String>, Vec<StorePath<String>>), Error> {
        let mut substitutions: HashMap<String, String> = HashMap::new();
        let mut input_sources: Vec<StorePath<String>> = Vec::new();

        for (dep_drv_path, resolved_dep) in combo {
            let dep_drv = self.derivations.get(dep_drv_path).ok_or_else(|| {
                Error::DerivationNotFound(dep_drv_path.clone())
            })?;
            for (unresolved_output, synthetic_ca_path) in &resolved_dep.outputs {
                let ia_path = dep_drv
                    .outputs
                    .get(&unresolved_output.output_name)
                    .and_then(|o| o.path.clone())
                    .ok_or_else(|| Error::UnknownReferencedOutput {
                        drv_path: dep_drv_path.clone(),
                        output_name: unresolved_output.output_name.clone(),
                    })?;
                substitutions.insert(ia_path, synthetic_ca_path.clone());
                let sp = StorePath::<String>::from_absolute_path(synthetic_ca_path.as_bytes())
                    .map_err(|e| Error::ConstructiveTrace(format!(
                        "synthetic CA path {} parse: {:?}",
                        synthetic_ca_path, e
                    )))?;
                input_sources.push(sp);
            }
        }

        // FOD udrvs are already content-addressed by declared hash — they
        // don't have IA-flavored output paths to rewrite, and we don't need
        // (or want) the closure walker to scan their outputs (which aren't
        // present in the verifier's local store, by design). Their ATerm has
        // no input-drv references to substitute either, so passing through
        // identity is correct.
        if udrv.is_fixed_output {
            return Ok((substitutions, input_sources));
        }

        // Local walker pass-1 over each output gives us the synthetic CA path
        // we'd need to substitute for this drv's own outputs. The walker
        // memoizes across calls so the closure is scanned once across the
        // whole verify run.
        let walker = self
            .walker
            .as_mut()
            .expect("IA branch requires the walker to be initialized");
        for udrv_output in udrv.outputs.values() {
            let ia_path = &udrv_output.unresolved_path;
            let synthetic = walker.synthetic_ca_path(ia_path)?;
            substitutions.insert(ia_path.clone(), synthetic.to_absolute_path());
        }

        Ok((substitutions, input_sources))
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
