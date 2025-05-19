use pyo3::prelude::*;
use datafrog::{Iteration, Variable, Relation, RelationLeaper};
use std::collections::{HashMap, HashSet};
use std::cmp::min;

use crate::string_interner::StringInterner;

#[pyclass(unsendable)]
pub struct TrustModelReasoner {
    interner: StringInterner,
    fill_iteration: Iteration,
    fods: Variable<(usize,usize)>,
    build_outputs: Variable<usize>,
    udrvs: Variable<usize>,
    udrv_outputs: Variable<usize>,
    udrvs_has_output_x: Variable<(usize,usize)>,
    udrvs_depends_on_x: Variable<(usize,usize)>,
    rdrvs: Variable<usize>,
    rdrvs_resolves_x: Variable<(usize,usize)>,
    rdrvs_resolve_x_with_y: Variable<(usize,usize,usize)>,
    rdrvs_outputs_x_as_y_says_z: Variable<(usize,usize,usize,usize)>, // (rdrv, build_output, udrv_output, trust_element)
    trusted_keys: Variable<usize>,
    threshold: usize,
    // Trust model relations
    trust_models: Variable<(usize,usize)>, // (trust_model_id, threshold)
    trust_model_members: Variable<(usize,usize)>, // (trust_model_id, member_id) where member can be a key or another trust model
}

#[pymethods]
impl TrustModelReasoner {
    #[new]
    fn new(trusted_keys: Vec<String>, threshold: usize) -> PyResult<Self> {
        // Check if trusted keys are provided
        if trusted_keys.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "No trusted keys configured. Please specify at least one trusted key using --trusted-key"
            ));
        }

        // Check if threshold is valid
        if threshold == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Threshold must be greater than 0"
            ));
        }

        if threshold > trusted_keys.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Threshold ({}) cannot exceed number of trusted keys ({})",
                    threshold, trusted_keys.len())
            ));
        }

        let mut fill_iteration = Iteration::new();

        let fods = fill_iteration.variable::<(usize,usize)>("fods");
        let build_outputs = fill_iteration.variable::<usize>("build_outputs");
        let udrvs = fill_iteration.variable::<usize>("udrvs");
        let udrv_outputs = fill_iteration.variable::<>("udrvs_outputs");
        let udrvs_has_output_x = fill_iteration.variable::<>("udrvs_has_output_x");
        let udrvs_depends_on_x = fill_iteration.variable::<(usize,usize)>("udrvs_depends_on_x");
        let rdrvs = fill_iteration.variable::<usize>("rdrvs");
        let rdrvs_resolves_x = fill_iteration.variable::<>("rdrvs_resolves_x");
        let rdrvs_resolve_x_with_y = fill_iteration.variable::<(usize,usize,usize)>("rdrvs_resolve_x_with_y");
        let rdrvs_outputs_x_as_y_says_z = fill_iteration.variable::<(usize,usize,usize,usize)>("rdrvs_outputs_x_as_y_says_z");
        let trusted_keys_var = fill_iteration.variable::<usize>("trusted_keys");
        let trust_models = fill_iteration.variable::<(usize,usize)>("trust_models");
        let trust_model_members = fill_iteration.variable::<(usize,usize)>("trust_model_members");

        let mut interner = StringInterner::new();

        // Intern the trusted keys and populate the variable
        let interned_keys: Vec<usize> = trusted_keys.iter()
            .map(|key| interner.intern(key))
            .collect();

        trusted_keys_var.extend(interned_keys.clone());

        // Create the default trust model
        let default_trust_model_id = interner.intern("default_trust_model");
        trust_models.extend(vec![(default_trust_model_id, threshold)]);

        // Add all trusted keys as members of the default trust model
        for &key in &interned_keys {
            trust_model_members.extend(vec![(default_trust_model_id, key)]);
        }

        Ok(TrustModelReasoner {
            interner,
            fill_iteration,
            fods,
            build_outputs,
            udrvs,
            udrv_outputs,
            udrvs_has_output_x,
            udrvs_depends_on_x,
            rdrvs,
            rdrvs_resolves_x,
            rdrvs_resolve_x_with_y,
            rdrvs_outputs_x_as_y_says_z,
            trusted_keys: trusted_keys_var,
            threshold,
            trust_models,
            trust_model_members,
        })
    }
    
    fn add_fod(&mut self, fod_to_add: &str, fod_hash_to_add: &str) -> Result<(), PyErr> {
        let fod_id = self.interner.intern(fod_to_add);
        let fod_hash_id = self.interner.intern(fod_hash_to_add);

        self.fods.extend(vec![(fod_id, fod_hash_id)]);
        self.udrvs.extend(vec![fod_id]);
        self.build_outputs.extend(vec![fod_hash_id]);

        // FODs have one output which is their content hash
        // We need to add this to udrvs_has_output_x so the cardinality initialization can find it
        let fod_output = self.interner.intern(&format!("{}$out", fod_to_add));
        self.udrv_outputs.extend(vec![fod_output]);
        self.udrvs_has_output_x.extend(vec![(fod_id, fod_output)]);

        println!("Added FOD: {} with hash {} and output {}",
            fod_to_add, fod_hash_to_add, self.interner.get_string(fod_output).unwrap_or("unknown"));

        Ok(())
    }
    
    fn add_unresolved_derivation(&mut self, udrv_to_add: &str, depends_on: Vec<String>, outputs: Vec<String>) -> Result<(), PyErr> {
        let udrv_id = self.interner.intern(udrv_to_add);
        self.udrvs.extend(vec![udrv_id]);

        println!("Adding unresolved derivation: {}", udrv_to_add);
        println!("  Dependencies: {:?}", depends_on);
        println!("  Outputs: {:?}", outputs);

        for item in depends_on.iter() {
            let dep_id = self.interner.intern(item);
            self.udrv_outputs.extend(vec![dep_id]);
            self.udrvs_depends_on_x.extend(vec![(udrv_id, dep_id)]);
            println!("  Added dependency: {} -> {}", udrv_to_add, item);
        }
        for item in outputs.iter() {
            let out_id = self.interner.intern(item);
            self.udrv_outputs.extend(vec![out_id]);
            self.udrvs_has_output_x.extend(vec![(udrv_id, out_id)]);
        }
        Ok(())
    }
    
    fn add_resolved_derivation(&mut self, resolves_udrv: &str, with_rdrv: &str, resolving_x_with_y: HashMap<String, String>) -> Result<(), PyErr> {
        self.udrvs.extend(vec![(self.interner.intern(resolves_udrv))]);
        self.rdrvs.extend(vec![(self.interner.intern(with_rdrv))]);
        self.rdrvs_resolves_x.extend(vec![(self.interner.intern(with_rdrv), self.interner.intern(resolves_udrv))]);

        for (key, value) in &resolving_x_with_y {
            self.udrv_outputs.extend(vec![(self.interner.intern(key))]);
            self.build_outputs.extend(vec![(self.interner.intern(value))]);

            // Don't add these as dependencies - they're resolution mappings, not dependencies
            // The actual dependencies were already added in add_unresolved_derivation
            self.rdrvs_resolve_x_with_y.extend(vec![(self.interner.intern(with_rdrv), self.interner.intern(key), self.interner.intern(value))]);
        }

        Ok(())
    }
    
    fn add_build_output_claim(&mut self, from_resolved: &str, building_x_into_y_says_z: HashMap<String, String>, according_to: &str) -> Result<(), PyErr> {
        let from_resolved_interned = self.interner.intern(from_resolved);
        self.rdrvs.extend(vec![from_resolved_interned]);
        let interned_key = self.interner.intern(according_to);

        // Populate the rdrvs_outputs_x_as_y_says_z relation
        for (as_output, to_built) in &building_x_into_y_says_z {
            let interned_output = self.interner.intern(as_output);
            let interned_built = self.interner.intern(to_built);

            println!("  Build output claim: {} -> {} (signed by {})",
                as_output, to_built, according_to);

            self.udrv_outputs.extend(vec![interned_output]);
            self.build_outputs.extend(vec![interned_built]);

            self.rdrvs_outputs_x_as_y_says_z.extend(vec![(
                from_resolved_interned,
                interned_built,
                interned_output,
                interned_key
            )]);
        }

        Ok(())
    }
    

    fn compute_result(&mut self) -> Result<Vec<String>, PyErr> {
        // We need to finalize the datafrog iteration once all facts are added
        // Just run the iteration to fixed point without more complex logic
        while self.fill_iteration.changed() {
            // Just iterate to fixed point without additional logic
        }

        // Complete all variables to relations
        let udrvs_depends_on_x_relation = self.udrvs_depends_on_x.clone().complete();
        let fods_relation = self.fods.clone().complete();
        let udrvs_relation = self.udrvs.clone().complete();
        let udrvs_has_output_x_relation = self.udrvs_has_output_x.clone().complete();
        let rdrvs_relation = self.rdrvs.clone().complete();
        let rdrvs_resolves_x_relation = self.rdrvs_resolves_x.clone().complete();
        let rdrvs_outputs_x_as_y_says_z_relation = self.rdrvs_outputs_x_as_y_says_z.clone().complete();
        let trust_models_relation = self.trust_models.clone().complete();
        let trust_model_members_relation = self.trust_model_members.clone().complete();

        // Start a new iteration for effective cardinality computation
        let mut cardinality_iteration = Iteration::new();

        // Trust results: (output, trust_element, cardinality)
        let trust_results = cardinality_iteration.variable::<(usize, usize, usize)>("trust_results");

        // Get the default trust model id for later use
        let default_trust_model_id = self.interner.intern("default_trust_model");

        println!("\n=== Trust Model Computation ===");

        // Initialize trust based on signatures and FODs
        let mut initial_trust = Vec::new();

        // Collect individual signatures and count them by trust model
        let mut trust_counts: HashMap<(usize, usize), usize> = HashMap::new();
        for &(_, _, udrv_output, signer) in rdrvs_outputs_x_as_y_says_z_relation.iter() {
            // For each trust model that this signer is a member of
            for &(trust_model, member) in trust_model_members_relation.iter() {
                if member == signer {
                    *trust_counts.entry((udrv_output, trust_model)).or_insert(0) += 1;
                }
            }
        }

        // Initialize trust model cardinalities based on member counts
        for ((output, trust_model), count) in trust_counts {
            let threshold = trust_models_relation.iter()
                .find(|&&(tm, _)| tm == trust_model)
                .map(|&(_, t)| t)
                .unwrap_or(self.threshold);

            if count >= threshold {
                initial_trust.push((output, trust_model, count));
                println!("  Output {} has trust model {} with cardinality {} (threshold: {})",
                    self.interner.get_string(output).unwrap_or("unknown"),
                    self.interner.get_string(trust_model).unwrap_or("unknown"),
                    count, threshold);
            }
        }

        // Add FODs with infinite trust for all trust models
        for &(fod, _) in fods_relation.iter() {
            for &(udrv, output) in udrvs_has_output_x_relation.iter() {
                if udrv == fod {
                    for &(trust_model, _) in trust_models_relation.iter() {
                        initial_trust.push((output, trust_model, usize::MAX));
                    }
                }
            }
        }

        trust_results.insert(Relation::from_vec(initial_trust));

        // Create candidates from all (output, trust_model) pairs
        let candidates = cardinality_iteration.variable::<(usize, usize)>("candidates");

        // Generate candidates more efficiently
        let all_candidates: Vec<(usize, usize)> = udrvs_has_output_x_relation.iter()
            .flat_map(|&(_, output)| {
                trust_models_relation.iter()
                    .map(move |&(trust_model, _)| (output, trust_model))
            })
            .collect();

        candidates.insert(Relation::from_vec(all_candidates));

        // Create dependency relation for our leapjoin
        let dep_relation = Relation::from_vec(
            udrvs_depends_on_x_relation.iter()
                .flat_map(|&(udrv, dep_output)| {
                    udrvs_has_output_x_relation.iter()
                        .filter(move |&&(u, _)| u == udrv)
                        .map(move |&(_, output)| (output, dep_output))
                })
                .collect()
        );

        // Run cardinality computation
        while cardinality_iteration.changed() {
            // Identify which candidates have all dependencies ready
            let ready_candidates: Vec<((usize, usize), usize)> = candidates.recent.borrow()
                .iter()
                .filter_map(|&(output, trust_element)| {
                    // Check if all dependencies are ready
                    let deps_ready = dep_relation.iter()
                        .filter(|&&(out, _)| out == output)
                        .all(|&(_, dep_out)| {
                            trust_results.recent.borrow()
                                .iter()
                                .chain(trust_results.stable.borrow().iter().flat_map(|b| b.iter()))
                                .any(|&(o, t, _)| o == dep_out && t == trust_element)
                        });

                    if deps_ready {
                        Some(((output, trust_element), 1))
                    } else {
                        None
                    }
                })
                .collect();

            let ready_relation = Relation::from_vec(ready_candidates);

            // Use leapjoin to compute effective cardinality
            trust_results.from_leapjoin(
                &candidates,
                ready_relation.extend_with(|&(output, trust_element)| (output, trust_element)),
                |&(output, trust_element), &_| {
                    // Get all dependency cardinalities
                    let dep_cards: Vec<usize> = dep_relation.iter()
                        .filter(|&&(from_output, _)| from_output == output)
                        .filter_map(|&(_, dep_out)| {
                            trust_results.recent.borrow()
                                .iter()
                                .chain(trust_results.stable.borrow().iter().flat_map(|b| b.iter()))
                                .find(|&&(o, t, _)| o == dep_out && t == trust_element)
                                .map(|&(_, _, card)| card)
                        })
                        .collect();

                    // Get current trust model cardinality
                    let trust_model_card = trust_results.recent.borrow()
                        .iter()
                        .chain(trust_results.stable.borrow().iter().flat_map(|b| b.iter()))
                        .find(|&&(o, t, _)| o == output && t == trust_element)
                        .map(|&(_, _, card)| card)
                        .unwrap_or(0);

                    // Get threshold
                    let threshold = trust_models_relation.iter()
                        .find(|&&(tm, _)| tm == trust_element)
                        .map(|&(_, t)| t)
                        .unwrap_or(self.threshold);

                    // Skip if already a FOD
                    if trust_model_card == usize::MAX {
                        return (output, trust_element, usize::MAX);
                    }

                    // Look for direct claims for this output
                    let output_claims = rdrvs_outputs_x_as_y_says_z_relation.iter()
                        .filter(|&(_, _, out, _)| *out == output)
                        .count();

                    let output_cardinality = if output_claims > 0 {
                        let direct_claims = rdrvs_outputs_x_as_y_says_z_relation.iter()
                            .filter(|&(_, _, out, signer)| {
                                *out == output &&
                                trust_model_members_relation.iter()
                                    .any(|&(tm, member)| tm == trust_element && member == *signer)
                            })
                            .count();

                        direct_claims
                    } else {
                        trust_model_card
                    };

                    // Compute effective cardinality
                    let min_dep = dep_cards.iter().copied().min().unwrap_or(usize::MAX);
                    let effective = if output_cardinality >= threshold {
                        if dep_cards.is_empty() {
                            output_cardinality
                        } else {
                            min(output_cardinality, min_dep)
                        }
                    } else {
                        0
                    };

                    println!("  Computed: output {} with {} -> cardinality {} (output: {}, min_dep: {})",
                        self.interner.get_string(output).unwrap_or("unknown"),
                        self.interner.get_string(trust_element).unwrap_or("unknown"),
                        effective,
                        output_cardinality,
                        if min_dep == usize::MAX { "∞".to_string() } else { min_dep.to_string() }
                    );

                    (output, trust_element, effective)
                }
            );
        }

        // Complete the trust computation and get the results
        let trust_results_final = trust_results.complete();

        // Find root derivation(s)
        // A root is a non-FOD derivation that is not a dependency of any other derivation
        let dependency_targets: HashSet<usize> = udrvs_depends_on_x_relation.iter()
            .map(|&(_, dep)| dep)
            .collect();

        let root_candidates: Vec<usize> = udrvs_relation.iter()
            .filter(|&&udrv| {
                // Not a dependency of any other derivation
                !udrvs_has_output_x_relation.iter()
                    .filter(|&&(u, output)| u == udrv)
                    .any(|&(_, output)| dependency_targets.contains(&output)) &&
                // Not a FOD
                !fods_relation.iter().any(|&(fod, _)| fod == udrv)
            })
            .copied()
            .collect();

        // (1) unresolved tree has one unique root
        if root_candidates.len() != 1 {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - Expected exactly one root derivation, found {}", root_candidates.len());
            println!("\nRoot candidates:");
            for &root in &root_candidates {
                println!("  - {}", self.interner.get_string(root).unwrap_or("unknown"));
            }
            return Ok(Vec::new());
        }

        let root_derivation = root_candidates[0];

        // Ensure all leaves are fixed-output derivations
        let non_fod_leaves: Vec<usize> = udrvs_relation.iter()
            .filter(|&&udrv| {
                // No outgoing dependencies
                udrvs_depends_on_x_relation.iter().all(|&(d, _)| d != udrv) &&
                // Not a FOD
                !fods_relation.iter().any(|&(fod, _)| fod == udrv)
            })
            .copied()
            .collect();

        if !non_fod_leaves.is_empty() {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - Found non-FOD leaf derivations");
            return Ok(Vec::new());
        }

        // Find which resolved derivations correspond to our root
        let resolved_roots: Vec<usize> = rdrvs_resolves_x_relation.iter()
            .filter(|&(_, udrv)| *udrv == root_derivation)
            .map(|&(rdrv, _)| rdrv)
            .collect();

        if resolved_roots.is_empty() {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - Root derivation {} was not resolved",
                self.interner.get_string(root_derivation).unwrap_or("unknown"));
            return Ok(Vec::new());
        }

        // Find which resolved derivations have sufficient cardinality
        let default_trust_model_id = self.interner.intern("default_trust_model");

        let verified_roots: Vec<usize> = resolved_roots.into_iter()
            .filter(|&rdrv| {
                // Find the root's outputs and check their effective cardinality
                let udrv = rdrvs_resolves_x_relation.iter()
                    .find(|&&(r, _)| r == rdrv)
                    .map(|&(_, u)| u)
                    .unwrap();

                // Find maximum cardinality across all outputs
                let max_cardinality = udrvs_has_output_x_relation.iter()
                    .filter(|&&(u, _)| u == udrv)
                    .filter_map(|&(_, output)| {
                        trust_results_final.iter()
                            .find(|&&(o, t, _)| o == output && t == default_trust_model_id)
                            .map(|&(_, _, cardinality)| cardinality)
                    })
                    .max()
                    .unwrap_or(0);

                // Check if it meets the threshold
                if max_cardinality >= self.threshold {
                    println!("✅ Root {} verified with effective cardinality {} (threshold: {})",
                        self.interner.get_string(rdrv).unwrap_or("unknown"),
                        max_cardinality, self.threshold);
                    true
                } else {
                    println!("❌ Root {} only has effective cardinality {} (threshold: {})",
                        self.interner.get_string(rdrv).unwrap_or("unknown"),
                        max_cardinality, self.threshold);
                    false
                }
            })
            .collect();

        if verified_roots.is_empty() {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - No roots had effective cardinality >= {}", self.threshold);
            return Ok(Vec::new());
        }

        // Generate summary information
        println!("\n=== Verification Results ===\n");

        let udrvs_count = udrvs_relation.len();
        let fods_count = fods_relation.len();
        let rdrvs_count = rdrvs_relation.len();
        let resolvable_count = udrvs_count - fods_count;

        println!("Build consists of {} unresolved derivations", udrvs_count);
        println!("with {} fixed-output derivations as leaves", fods_count);

        if resolvable_count > 0 {
            println!("Resolved {}/{} derivations via signatures", rdrvs_count, resolvable_count);
        }

        println!("\nVerification status:");
        println!("✅ The root derivation [{}] was successfully resolved",
                 self.interner.get_string(root_derivation).unwrap_or("unknown"));

        // Convert verified roots to strings for return value
        let resolved_root_strings: Vec<String> = verified_roots
            .iter()
            .map(|&rdrv| self.interner.get_string(rdrv).unwrap_or("unknown").to_string())
            .collect();

        Ok(resolved_root_strings)

        // TODO: take into account different possible ways of unification
        // if this a 1:1 relationship unification is total, or we reject builds - no frankenbuilds
        // if it is a 1:n relationship unification is partial, and we have to do rewriting
        
        // in parctice we could make unification only total in terms of runtime closures
        // and have it be ok if it is not total for build time closures


        // on a philosopical level I do not think we would need the ability to model
        // resolving different outputs of the same derivation differently
        // but practically thats exactly what legacy signatures end up allowing
        // so I am not sure where we land there

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::prelude::*;

    #[test]
    fn test_trust_propagation() -> Result<(), PyErr> {
        env_logger::init();
        // Create a reasoner with 2 trusted keys and threshold 2
        let mut reasoner = TrustModelReasoner::new(vec!["key1".to_string(), "key2".to_string()], 2)?;

        // Add a simple chain: fod -> dep -> output
        reasoner.add_fod("fod1", "hash1")?;
        reasoner.add_unresolved_derivation("dep1", vec!["fod1$out".to_string()], vec!["dep1$out".to_string()])?;
        reasoner.add_unresolved_derivation("output1", vec!["dep1$out".to_string()], vec!["output1$out".to_string()])?;

        // Add resolved derivations
        reasoner.add_resolved_derivation("dep1", "resolved_dep1",
            vec![("dep1$out".to_string(), "build_dep1".to_string())].into_iter().collect())?;
        reasoner.add_resolved_derivation("output1", "resolved_output1",
            vec![("output1$out".to_string(), "build_output1".to_string())].into_iter().collect())?;

        // Add signatures from both keys
        reasoner.add_build_output_claim("resolved_dep1",
            vec![("dep1$out".to_string(), "build_dep1".to_string())].into_iter().collect(),
            "key1")?;
        reasoner.add_build_output_claim("resolved_dep1",
            vec![("dep1$out".to_string(), "build_dep1".to_string())].into_iter().collect(),
            "key2")?;
        reasoner.add_build_output_claim("resolved_output1",
            vec![("output1$out".to_string(), "build_output1".to_string())].into_iter().collect(),
            "key1")?;
        reasoner.add_build_output_claim("resolved_output1",
            vec![("output1$out".to_string(), "build_output1".to_string())].into_iter().collect(),
            "key2")?;

        // Run the computation
        let result = reasoner.compute_result()?;

        // Check that we get a result
        if result.is_empty() {
            panic!("Expected non-empty result from trust computation");
        }

        Ok(())
    }
}