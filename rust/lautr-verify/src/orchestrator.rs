//! End-to-end verification orchestrator.
//!
//! One DFS over the derivation graph: each udrv visit builds its
//! `UnresolvedDerivation`, feeds the verifier's facts, and returns the set of
//! plausible resolutions for that udrv. Memo on drv_path ensures each udrv is
//! processed once even when it sits under multiple parents.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;

use lautr_core::{constructive_trace, store_path, thumbprint};

use crate::backend::{self, Backend};
use crate::debug::{DebugProbe, LocalWitness, NullProbe};
use crate::drv_json::{self, DrvJson};
use crate::signature_verify;
use crate::string_interner::{ContentHash, KeyId, OutputName, StringInterner, UDrv};
use crate::types::{
    TrustlesslyResolvedDerivation, UnresolvedDerivation, UnresolvedOutput,
    UnresolvedReferencedInputs,
};
use crate::verifier::{Facts, Subset, TrustModel, Verifier, VerifyResult};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("backend: {0}")]
    Backend(#[from] backend::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("derivation {0:?} not found in recursive listing")]
    DerivationNotFound(String),
    #[error(
        "input referenced output {output_name:?} not declared on input derivation {drv_path:?}"
    )]
    UnknownReferencedOutput { drv_path: String, output_name: String },
    #[error("cannot handle IA derivations yet")]
    InputAddressedNotAllowed,
    #[error("FOD {drv_path:?} is missing 'out' output path")]
    FodMissingOut { drv_path: String },
    #[error("constructive trace: {0}")]
    ConstructiveTrace(String),
    #[error("store path: {0}")]
    StorePath(#[from] store_path::Error),
    #[error("signature verify: {0}")]
    SignatureVerify(#[from] signature_verify::Error),
    #[error("thumbprint: {0}")]
    Thumbprint(#[from] thumbprint::Error),
    #[error("trust model: {0}")]
    TrustModel(String),
}

/// Configuration knobs from the verify CLI surface.
pub struct Config {
    pub root_drv_path: String,
    pub cache_urls: Vec<String>,
    /// `(key_name, raw_32_byte_public_key)` for each trusted key.
    pub trusted_keys: Vec<(String, Vec<u8>)>,
    pub allow_ia: bool,
    /// Defaults to a `NullProbe`; the verify CLI swaps in a `DifftProbe` when
    /// `--debug-preimage-corpus` is set.
    pub debug_probe: Box<dyn DebugProbe>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            root_drv_path: String::new(),
            cache_urls: Vec::new(),
            trusted_keys: Vec::new(),
            allow_ia: false,
            debug_probe: Box::new(NullProbe),
        }
    }
}

pub struct Orchestrator<B: Backend> {
    backend: B,
    cache_urls: Vec<String>,
    /// `(kid, raw_key)` for verification + reasoner; `kid` is `name:thumbprint16`.
    trusted_keys: Vec<(String, Vec<u8>)>,
    allow_ia: bool,
    debug_probe: Box<dyn DebugProbe>,

    derivations: HashMap<String, DrvJson>,

    interner: StringInterner,
    facts: Facts,
    trust_model: TrustModel,
    expected_root: UDrv,

    /// `drv_path -> unresolved derivation`. Replaces the Python `@cache`.
    tree_memo: HashMap<String, Arc<UnresolvedDerivation>>,
    /// `drv_path -> set of plausible resolutions`. Replaces the Python `@cache`.
    resolutions_memo: HashMap<String, Vec<TrustlesslyResolvedDerivation>>,
    /// `input_hash -> fetched-and-verified (payload, kid)` pairs. Caches a
    /// network + crypto cost across resolution combinations.
    sig_memo: HashMap<String, Vec<(Value, String)>>,
}

impl<B: Backend> Orchestrator<B> {
    pub fn new(backend: B, cfg: Config) -> Result<Self, Error> {
        if cfg.trusted_keys.is_empty() {
            return Err(Error::TrustModel(
                "No trusted keys configured. Please specify at least one trusted key using --trusted-key".to_owned(),
            ));
        }

        // Resolve names → `kid` so both verification and the trust model use
        // the same string representation. The kid head is the first 16 chars
        // of the JWK thumbprint, matching what the signer puts in the JWS.
        let mut kid_keys: Vec<(String, Vec<u8>)> = Vec::with_capacity(cfg.trusted_keys.len());
        for (name, key_bytes) in &cfg.trusted_keys {
            let tp = thumbprint::ed25519_thumbprint(key_bytes)?;
            let kid = format!("{}:{}", name, &tp[..16]);
            kid_keys.push((kid, key_bytes.clone()));
        }

        let recursive_json = backend.derivation_show_recursive(&cfg.root_drv_path)?;
        let derivations: HashMap<String, DrvJson> = serde_json::from_str(&recursive_json)?;

        let mut interner = StringInterner::new();
        let key_ids: Vec<KeyId> = kid_keys.iter().map(|(k, _)| interner.key(k)).collect();
        let threshold = key_ids.len();
        let trust_model = TrustModel::Threshold(
            threshold,
            key_ids.into_iter().map(TrustModel::Key).collect(),
        );
        trust_model.validate().map_err(Error::TrustModel)?;
        let expected_root = interner.udrv(&cfg.root_drv_path);

        Ok(Self {
            backend,
            cache_urls: cfg.cache_urls,
            trusted_keys: kid_keys,
            allow_ia: cfg.allow_ia,
            debug_probe: cfg.debug_probe,
            derivations,
            interner,
            facts: Facts::new(),
            trust_model,
            expected_root,
            tree_memo: HashMap::new(),
            resolutions_memo: HashMap::new(),
            sig_memo: HashMap::new(),
        })
    }

    /// Run the full verification: walks the graph, feeds the verifier, then
    /// evaluates every candidate output map. Returns a description of every
    /// candidate that verified (empty vec means failure).
    pub fn verify(&mut self) -> Result<Vec<String>, Error> {
        let root_drv_path = self
            .interner
            .udrv_str(self.expected_root)
            .map(str::to_owned)
            .expect("expected_root interned at construction");
        let root_udrv = self.build_unresolved(&root_drv_path)?;
        let _ = self.collect_resolutions(&root_udrv)?;

        let candidates = collect_candidate_output_maps(&self.facts, self.expected_root);
        if candidates.is_empty() {
            eprintln!(
                "[laut verify] no signed claims found for root udrv {}",
                root_drv_path
            );
            return Ok(Vec::new());
        }

        let mut verifier = Verifier::new(&self.facts, &self.trust_model).map_err(Error::TrustModel)?;

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
                root_drv_path
            );
            for (subset, result) in &successes {
                self.print_success_summary(subset, result);
            }
        } else {
            eprintln!(
                "[laut verify] verification FAILED — all {} candidate output map(s) at the root rejected:",
                failures.len()
            );
            for f in &failures {
                eprint!("{}", f);
            }
        }

        Ok(verified)
    }

    // ---------------- Tree construction ----------------

    fn build_unresolved(&mut self, drv_path: &str) -> Result<Arc<UnresolvedDerivation>, Error> {
        if let Some(existing) = self.tree_memo.get(drv_path) {
            return Ok(existing.clone());
        }

        let drv = self
            .derivations
            .get(drv_path)
            .ok_or_else(|| Error::DerivationNotFound(drv_path.to_owned()))?
            .clone();
        let (is_fixed_output, is_content_addressed) = drv_json::classify(&drv.outputs);

        let outputs = build_outputs(drv_path, &drv, is_content_addressed)?;
        let fod_out_path = if is_fixed_output {
            Some(
                drv.outputs
                    .get("out")
                    .and_then(|o| o.path.clone())
                    .ok_or_else(|| Error::FodMissingOut {
                        drv_path: drv_path.to_owned(),
                    })?,
            )
        } else {
            None
        };

        let inputs = if is_fixed_output {
            Vec::new()
        } else if is_content_addressed || self.allow_ia {
            let mut acc = Vec::with_capacity(drv.input_drvs.len());
            for (input_drv_path, input_ref) in &drv.input_drvs {
                let child = self.build_unresolved(input_drv_path)?;
                let mut referenced: BTreeMap<String, UnresolvedOutput> = BTreeMap::new();
                for output_name in &input_ref.outputs {
                    let output = child.outputs.get(output_name).ok_or_else(|| {
                        Error::UnknownReferencedOutput {
                            drv_path: input_drv_path.clone(),
                            output_name: output_name.clone(),
                        }
                    })?;
                    referenced.insert(output_name.clone(), output.clone());
                }
                acc.push(UnresolvedReferencedInputs {
                    derivation: child,
                    inputs: referenced,
                });
            }
            acc
        } else {
            return Err(Error::InputAddressedNotAllowed);
        };

        let unresolved = Arc::new(UnresolvedDerivation {
            drv_path: drv_path.to_owned(),
            name: drv.name.clone(),
            input_hash: store_path::extract_store_hash(drv_path)?,
            outputs,
            inputs,
            is_fixed_output,
            is_content_addressed,
            fod_out_path,
        });
        self.tree_memo
            .insert(drv_path.to_owned(), unresolved.clone());
        Ok(unresolved)
    }

    // ---------------- Resolution collection ----------------

    fn collect_resolutions(
        &mut self,
        udrv: &Arc<UnresolvedDerivation>,
    ) -> Result<Vec<TrustlesslyResolvedDerivation>, Error> {
        if let Some(existing) = self.resolutions_memo.get(&udrv.drv_path) {
            return Ok(existing.clone());
        }

        if udrv.is_fixed_output {
            let fod_out_path = udrv.fod_out_path.as_deref().ok_or_else(|| Error::FodMissingOut {
                drv_path: udrv.drv_path.clone(),
            })?;
            let (ct_input_hash, _aterm_bytes) = self.compute_resolved(udrv, &BTreeMap::new())?;
            self.add_fod_to_facts(udrv, fod_out_path);
            let out_output = udrv.outputs.get("out").cloned().ok_or_else(|| {
                Error::UnknownReferencedOutput {
                    drv_path: udrv.drv_path.clone(),
                    output_name: "out".to_owned(),
                }
            })?;
            let mut outs = BTreeMap::new();
            outs.insert(out_output, fod_out_path.to_owned());
            let resolved = TrustlesslyResolvedDerivation {
                resolves: udrv.clone(),
                drv_path: None,
                input_hash: ct_input_hash,
                outputs: outs,
            };
            let result = vec![resolved];
            self.resolutions_memo
                .insert(udrv.drv_path.clone(), result.clone());
            return Ok(result);
        }

        // Recurse first; if any dep can't be resolved, this udrv is unresolvable.
        let mut dep_resolutions: Vec<(Arc<UnresolvedDerivation>, Vec<TrustlesslyResolvedDerivation>)> =
            Vec::with_capacity(udrv.inputs.len());
        for input in &udrv.inputs {
            let child = self.collect_resolutions(&input.derivation)?;
            if child.is_empty() {
                self.resolutions_memo
                    .insert(udrv.drv_path.clone(), Vec::new());
                return Ok(Vec::new());
            }
            dep_resolutions.push((input.derivation.clone(), child));
        }

        self.add_unresolved_to_facts(udrv);

        let mut plausible: Vec<TrustlesslyResolvedDerivation> = Vec::new();
        let mut seen_resolution_hashes: HashSet<String> = HashSet::new();
        for combo in cartesian_product(&dep_resolutions) {
            let (ct_input_hash, aterm_bytes) = self.compute_resolved(udrv, &combo)?;
            // Avoid pushing the same `(udrv, ct_input_hash, output_map)` twice
            // when distinct dep choices happen to collapse to the same resolved
            // input hash (rare but possible).
            self.add_resolved_to_facts(udrv, &ct_input_hash, &combo);

            let signatures = self.fetch_and_verify_signatures(&ct_input_hash)?;
            if signatures.is_empty() {
                self.debug_probe.on_signature_miss(&LocalWitness {
                    udrv_drv_path: &udrv.drv_path,
                    udrv_name: &udrv.name,
                    udrv_input_hash: &udrv.input_hash,
                    ct_input_hash: &ct_input_hash,
                    aterm_bytes: &aterm_bytes,
                });
                continue;
            }
            for (payload, kid) in signatures {
                let nix_outputs = payload
                    .get("out")
                    .and_then(|v| v.get("nix"))
                    .and_then(|v| v.as_object());
                let Some(nix_outputs) = nix_outputs else {
                    continue;
                };
                // Single content-keyed map: `UnresolvedOutput` lookups give us
                // both the value the verifier wants and a stable iteration
                // order for the dedup key. No parallel structure.
                let mut outputs: BTreeMap<UnresolvedOutput, String> = BTreeMap::new();
                let mut consistent = true;
                for (output_name, claim) in nix_outputs {
                    let Some(path) = claim.get("path").and_then(|v| v.as_str()) else {
                        consistent = false;
                        break;
                    };
                    let Some(udrv_output) = udrv.outputs.get(output_name) else {
                        // Signer claimed an output we don't have — skip claim.
                        consistent = false;
                        break;
                    };
                    outputs.insert(udrv_output.clone(), path.to_owned());
                }
                if !consistent {
                    continue;
                }
                self.add_claim_to_facts(&ct_input_hash, &kid, &outputs);

                let dedup_key = format!(
                    "{}:{}",
                    ct_input_hash,
                    outputs
                        .iter()
                        .map(|(o, v)| format!("{}={}", o.output_name, v))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                if !seen_resolution_hashes.insert(dedup_key) {
                    // Same (ct_input_hash, outputs) we already recorded;
                    // skip this signer's identical copy.
                    continue;
                }
                let resolved_drv_path = self.compute_resolved_drv_path(udrv, &combo)?;
                plausible.push(TrustlesslyResolvedDerivation {
                    resolves: udrv.clone(),
                    drv_path: Some(resolved_drv_path),
                    input_hash: ct_input_hash.clone(),
                    outputs,
                });
            }
        }

        self.resolutions_memo
            .insert(udrv.drv_path.clone(), plausible.clone());
        Ok(plausible)
    }

    // ---------------- Facts feeding ----------------

    fn add_fod_to_facts(&mut self, udrv: &UnresolvedDerivation, out_path: &str) {
        let id = self.interner.udrv(&udrv.drv_path);
        let out = self.interner.output_name("out");
        let ch = self.interner.content_hash(out_path);
        let mut outputs = HashMap::new();
        outputs.insert(out, ch);
        self.facts.add_fod(id, outputs);
    }

    fn add_unresolved_to_facts(&mut self, udrv: &UnresolvedDerivation) {
        let _ = self.interner.udrv(&udrv.drv_path);
    }

    fn add_resolved_to_facts(
        &mut self,
        udrv: &UnresolvedDerivation,
        ct_input_hash: &str,
        combo: &BTreeMap<String, TrustlesslyResolvedDerivation>,
    ) {
        let udrv_id = self.interner.udrv(&udrv.drv_path);
        let rdrv_id = self.interner.rdrv(ct_input_hash);

        let mut dep_resolutions: HashMap<(UDrv, OutputName), ContentHash> = HashMap::new();
        for resolved in combo.values() {
            let dep_udrv_id = self.interner.udrv(&resolved.resolves.drv_path);
            for (unresolved_output, content_hash) in &resolved.outputs {
                let output_id = self.interner.output_name(&unresolved_output.output_name);
                let hash_id = self.interner.content_hash(content_hash);
                dep_resolutions.insert((dep_udrv_id, output_id), hash_id);
            }
        }
        self.facts.add_rdrv(rdrv_id, udrv_id, dep_resolutions);
    }

    fn add_claim_to_facts(
        &mut self,
        ct_input_hash: &str,
        kid: &str,
        outputs: &BTreeMap<UnresolvedOutput, String>,
    ) {
        let rdrv = self.interner.rdrv(ct_input_hash);
        let signer = self.interner.key(kid);
        let mut interned_outputs: HashMap<OutputName, ContentHash> = HashMap::new();
        for (udrv_output, content_hash) in outputs {
            let out = self.interner.output_name(&udrv_output.output_name);
            let ch = self.interner.content_hash(content_hash);
            interned_outputs.insert(out, ch);
        }
        self.facts.add_claim(rdrv, signer, interned_outputs);
    }

    // ---------------- Hashing + signature plumbing ----------------

    /// Returns `(ct_input_hash, aterm_bytes_string)` for `udrv` under the given
    /// resolution. `combo` is empty for FODs / leaves.
    fn compute_resolved(
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
    fn compute_resolved_drv_path(
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

    fn fetch_and_verify_signatures(
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
        let results =
            signature_verify::verify_resolved_trace_signatures(input_hash, signatures, &self.trusted_keys)?;
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

    // ---------------- Result formatting (lifted from trust_model_reasoner.rs) ----------------

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
        eprintln!(
            "  signers contributing to the bundle: {{{}}}",
            signer_names.join(", ")
        );
    }

    fn format_verification_failure(&self, subset: &Subset, result: &VerifyResult) -> String {
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

// ---------------- Free helpers ----------------

/// Build the unresolved-output map for a derivation. Mirrors
/// `get_all_outputs_of_drv` in the Python.
fn build_outputs(
    drv_path: &str,
    drv: &DrvJson,
    is_content_addressed: bool,
) -> Result<BTreeMap<String, UnresolvedOutput>, Error> {
    let mut out = BTreeMap::new();
    for (output_name, output_ref) in &drv.outputs {
        let (input_hash, unresolved_path) = if is_content_addressed {
            (None, format!("{}${}", drv_path, output_name))
        } else {
            let path = output_ref.path.clone().ok_or_else(|| {
                Error::UnknownReferencedOutput {
                    drv_path: drv_path.to_owned(),
                    output_name: output_name.clone(),
                }
            })?;
            let hash = store_path::extract_store_hash(&path)?;
            (Some(hash), path)
        };
        out.insert(
            output_name.clone(),
            UnresolvedOutput {
                output_name: output_name.clone(),
                drv_path: drv_path.to_owned(),
                input_hash,
                unresolved_path,
            },
        );
    }
    Ok(out)
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

/// Iterate every assignment of one resolution per dep, in stable order.
/// Returns assignments keyed by the dep's drv_path so the caller can look up
/// the chosen resolution without holding on to dep `UnresolvedDerivation`s.
pub fn cartesian_product(
    dep_resolutions: &[(Arc<UnresolvedDerivation>, Vec<TrustlesslyResolvedDerivation>)],
) -> Vec<BTreeMap<String, TrustlesslyResolvedDerivation>> {
    if dep_resolutions.is_empty() {
        return vec![BTreeMap::new()];
    }
    let mut acc: Vec<BTreeMap<String, TrustlesslyResolvedDerivation>> = vec![BTreeMap::new()];
    for (dep, options) in dep_resolutions {
        let mut next: Vec<BTreeMap<String, TrustlesslyResolvedDerivation>> =
            Vec::with_capacity(acc.len() * options.len());
        for prefix in &acc {
            for choice in options {
                let mut extended = prefix.clone();
                extended.insert(dep.drv_path.clone(), choice.clone());
                next.push(extended);
            }
        }
        acc = next;
    }
    acc
}

/// Collect every output map that some signed rdrv-claim claims for the root udrv.
/// These become the candidate verification targets. Lifted from the old
/// `trust_model_reasoner.rs`.
pub fn collect_candidate_output_maps(facts: &Facts, root_udrv: UDrv) -> Vec<Subset> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cartesian_empty_yields_singleton_empty_map() {
        let result = cartesian_product(&[]);
        assert_eq!(result.len(), 1);
        assert!(result[0].is_empty());
    }

    #[test]
    fn cartesian_single_dep_one_option() {
        let dep = Arc::new(UnresolvedDerivation {
            drv_path: "/nix/store/a.drv".into(),
            name: "a".into(),
            input_hash: "a".into(),
            outputs: BTreeMap::new(),
            inputs: Vec::new(),
            is_fixed_output: false,
            is_content_addressed: true,
            fod_out_path: None,
        });
        let resolved = TrustlesslyResolvedDerivation {
            resolves: dep.clone(),
            drv_path: None,
            input_hash: "h".into(),
            outputs: BTreeMap::new(),
        };
        let result = cartesian_product(&[(dep.clone(), vec![resolved])]);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains_key("/nix/store/a.drv"));
    }

    #[test]
    fn cartesian_multi_dep_multiplies() {
        let mk = |p: &str| {
            Arc::new(UnresolvedDerivation {
                drv_path: p.into(),
                name: p.into(),
                input_hash: p.into(),
                outputs: BTreeMap::new(),
                inputs: Vec::new(),
                is_fixed_output: false,
                is_content_addressed: true,
                fod_out_path: None,
            })
        };
        let mk_resolved = |dep: Arc<UnresolvedDerivation>, h: &str| TrustlesslyResolvedDerivation {
            resolves: dep,
            drv_path: None,
            input_hash: h.into(),
            outputs: BTreeMap::new(),
        };
        let a = mk("a");
        let b = mk("b");
        let result = cartesian_product(&[
            (a.clone(), vec![mk_resolved(a.clone(), "a1"), mk_resolved(a.clone(), "a2")]),
            (b.clone(), vec![mk_resolved(b.clone(), "b1"), mk_resolved(b.clone(), "b2")]),
        ]);
        assert_eq!(result.len(), 4);
    }
}
