//! Resolution collection: for each udrv, enumerate the cartesian product over
//! its deps' plausible resolutions, fetch signatures for each candidate, and
//! feed the resulting facts into the verifier.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::backend::Backend;
use crate::debug::LocalWitness;
use crate::string_interner::{ContentHash, OutputName, UDrv};
use crate::types::{TrustlesslyResolvedDerivation, UnresolvedDerivation, UnresolvedOutput};

use super::{Error, Orchestrator};

impl<B: Backend> Orchestrator<B> {
    pub(super) fn collect_resolutions(
        &mut self,
        udrv: &Arc<UnresolvedDerivation>,
    ) -> Result<Vec<TrustlesslyResolvedDerivation>, Error> {
        if let Some(existing) = self.resolutions_memo.get(&udrv.drv_path) {
            return Ok(existing.clone());
        }

        if udrv.is_fixed_output {
            let fod_out_path = udrv.fod_out_path.as_deref().ok_or_else(|| {
                Error::FodMissingOut {
                    drv_path: udrv.drv_path.clone(),
                }
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
