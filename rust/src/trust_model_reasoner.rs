use pyo3::prelude::*;
use datafrog::{Iteration, Variable, Relation, RelationLeaper, ValueFilter};
use std::collections::{HashMap, HashSet};
use std::cell::RefCell;

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
    rdrvs_outputs_x_as_y_says_z: Variable<(usize,usize,usize,usize)>, // (rdrv, build_output, udrv_output, trust_model_id)
    trust_models: Variable<(usize,usize,bool,Option<usize>)>, // (trust_model_id, threshold, is_key, is_member_of)
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
        let trust_models = fill_iteration.variable::<(usize,usize,bool,Option<usize>)>("trust_models");

        let mut interner = StringInterner::new();

        // Intern the trusted keys
        let interned_keys: Vec<usize> = trusted_keys.iter()
            .map(|key| interner.intern(key))
            .collect();

        // Create the default trust model
        let default_trust_model_id = interner.intern("default_trust_model");

        // Add the default trust model with its threshold
        // (id, threshold, is_key=false, is_member_of=None)
        trust_models.extend(vec![(default_trust_model_id, threshold, false, None)]);

        // Add all trusted keys as entries with is_key=true and member_of=default_trust_model
        for &key in &interned_keys {
            // (id, threshold=1, is_key=true, is_member_of=Some(default_trust_model_id))
            trust_models.extend(vec![(key, 1, true, Some(default_trust_model_id))]);
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
            trust_models,
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

        println!("\n=== Trust Models Configuration ===");
        for &(tm_id, threshold, is_key, member_of) in trust_models_relation.iter() {
            println!("Trust model: {} (threshold: {}, is_key: {}, member_of: {:?})",
                self.interner.get_string(tm_id).unwrap_or("unknown"),
                threshold,
                is_key,
                member_of.map(|id| self.interner.get_string(id).unwrap_or("unknown"))
            );
        }

        // Create relation of trust models by membership
        let trust_models_relation_by_is_member_of = Relation::from_vec(
            trust_models_relation.iter()
                .filter_map(|&(trust_model_id, threshold, is_key, is_member_of)| {
                    // Only include entries that have a parent model
                    is_member_of.map(|parent_id| (parent_id, (trust_model_id, threshold, is_key)))
                })
                .collect()
        );

        // Create relation of trust model thresholds
        let trust_models_relation_thresholds = Relation::from_vec(
            trust_models_relation.iter()
                .map(|&(trust_model_id, threshold, _, _)| (trust_model_id, threshold))
                .collect()
        );

        let trust_model_id_and_parent_id_with_threshold = Relation::from_join(&trust_models_relation_by_is_member_of, &trust_models_relation_thresholds, |&parent_trust_model_id, &(trust_model_id, threshold, is_key), &parent_threshold | (trust_model_id, (parent_trust_model_id, parent_threshold)));

        println!("\n=== Trust Model Propagation Relationships ===");
        for &(child_tm, (parent_tm, parent_threshold)) in trust_model_id_and_parent_id_with_threshold.iter() {
            println!("Child: {} -> Parent: {} (parent_threshold: {})",
                self.interner.get_string(child_tm).unwrap_or("unknown"),
                self.interner.get_string(parent_tm).unwrap_or("unknown"),
                parent_threshold
            );
        }

        // Start a new iteration for effective cardinality computation
        let mut cardinality_iteration = Iteration::new();

        // Variable for storing both direct key claims and trust model claims
        let rdrvs_outputs_x_as_y_by_tm = cardinality_iteration.variable::<(usize,(usize,usize,usize))>("rdrvs_outputs_x_as_y_by_tm");

        // First, copy all existing key signatures directly
        let initial_signatures = Relation::from_vec(
            rdrvs_outputs_x_as_y_says_z_relation.iter()
                .map(|&(rdrv, build_output, udrv_output, trust_model_id)|
                    (trust_model_id, (rdrv, build_output, udrv_output)))
                .collect()
        );
        rdrvs_outputs_x_as_y_by_tm.insert(initial_signatures);

        // Create a HashMap to track effective cardinalities, indexed by (trust_model_id, rdrv, build_output, udrv_output)
        // Wrap it in a RefCell to allow mutation from within closures
        let effective_tm_cardinalities = RefCell::new(HashMap::<(usize, usize, usize, usize), usize>::new());

        let mut iteration_count = 0;
        while cardinality_iteration.changed() {
            iteration_count += 1;
            println!("\n--- Cardinality Iteration {} ---", iteration_count);

            // The from_leapjoin pattern should use a tuple of extension with filter, and then a mapping function
            rdrvs_outputs_x_as_y_by_tm.from_leapjoin(
                &rdrvs_outputs_x_as_y_by_tm,
                // First argument: tuple of (extension, filter)
                (
                    trust_model_id_and_parent_id_with_threshold.extend_with(|&(trust_model_id, (_, _, _))| trust_model_id),
                    ValueFilter::from(|&(trust_model_id, (rdrv, build_output, udrv_output)), &(parent_trust_model_id, parent_threshold)| {
                        // Create a key for the HashMap
                        let key = (parent_trust_model_id, rdrv, build_output, udrv_output);

                        // Get current value from HashMap via RefCell, defaulting to 0
                        let mut cardinalities = effective_tm_cardinalities.borrow_mut();
                        let current_val = *cardinalities.get(&key).unwrap_or(&0);

                        // Calculate new value and update HashMap
                        let new_val = current_val + 1;
                        cardinalities.insert(key, new_val);

                        // Only emit when we exactly reach the threshold
                        parent_threshold == new_val
                    })
                ),
                // Second argument: mapping function
                |&(_, (rdrv, build_output, udrv_output)), &(parent_trust_model_id, _)|
                    (parent_trust_model_id, (rdrv, build_output, udrv_output))
            );

            println!("Iteration added {} facts", rdrvs_outputs_x_as_y_by_tm.recent.borrow().len());
        }


        // Complete the trust computation and get the results
        let rdrvs_outputs_x_as_y_by_tm = rdrvs_outputs_x_as_y_by_tm.complete();

        println!("\n=== Trust Model Computation Results ===");
        println!("Total number of trust model claims: {}", rdrvs_outputs_x_as_y_by_tm.len());

        // Group claims by trust model for better readability
        let mut claims_by_model: HashMap<usize, Vec<(usize, usize, usize)>> = HashMap::new();
        for &(tm_id, tuple) in rdrvs_outputs_x_as_y_by_tm.iter() {
            claims_by_model.entry(tm_id).or_insert_with(Vec::new).push(tuple);
        }
        for (tm_id, claims) in claims_by_model.iter() {
            println!("\nTrust model: {}", self.interner.get_string(*tm_id).unwrap_or("unknown"));
            println!("  Number of claims: {}", claims.len());

            // Check if this is the default trust model
            let default_trust_model_id = self.interner.intern("default_trust_model");
            if *tm_id == default_trust_model_id {
                println!("  *** This is the DEFAULT TRUST MODEL ***");
            }

            println!("  Claims:");
            for (rdrv, build_output, udrv_output) in claims {
                println!("    - Resolved derivation: {}", self.interner.get_string(*rdrv).unwrap_or("unknown"));
                println!("      Output: {} -> {}",
                    self.interner.get_string(*udrv_output).unwrap_or("unknown"),
                    self.interner.get_string(*build_output).unwrap_or("unknown"));
            }
        }

        println!("\nEffective cardinalities:");
        let cardinalities = effective_tm_cardinalities.borrow();
        for ((tm_id, rdrv, build_output, udrv_output), count) in cardinalities.iter() {
            if *count > 0 {
                println!("  Trust model: {}, RDRV: {}, Output: {} -> {}, Count: {}",
                    self.interner.get_string(*tm_id).unwrap_or("unknown"),
                    self.interner.get_string(*rdrv).unwrap_or("unknown"),
                    self.interner.get_string(*udrv_output).unwrap_or("unknown"),
                    self.interner.get_string(*build_output).unwrap_or("unknown"),
                    count);
            }
        }

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

        println!("🚧 note that the following verification does NOT yet\n  * {}\n  * {}",
            "properly ensure build steps link up or",
            "recognize that a group of build steps forms a sufficiently reproducible unit");
        println!("\nIt effectifly only displays information about the reproducibility of the last step.\n");

        let verified_roots: Vec<usize> = resolved_roots.into_iter()
            .filter(|&rdrv| {
                // Find the root's outputs and check their effective cardinality
                let udrv = rdrvs_resolves_x_relation.iter()
                    .find(|&&(r, _)| r == rdrv)
                    .map(|&(_, u)| u)
                    .unwrap();

                let root_outputs: Vec<usize> = udrvs_has_output_x_relation.iter()
                    .filter(|&&(u, _)| u == udrv)
                    .map(|&(_, output)| output)
                    .collect();

                let verified_outputs_min_output_cardinality = rdrvs_outputs_x_as_y_by_tm.iter()
                        .filter(|&(tm_id, (r, _, o))| 
                    *tm_id == default_trust_model_id && *r == rdrv && root_outputs.contains(o))
                        .map(|&(k, (r, t, o))| {
                            let mut cardinalities = effective_tm_cardinalities.borrow();

                            *cardinalities.get(&(k,r,t,o)).unwrap()
                        })
                        .min().unwrap();

                let default_threshold = trust_models_relation.iter()
                    .find(|&&(tm_id, _, _, _)| tm_id == default_trust_model_id)
                    .map(|&(_, threshold, _, _)| threshold)
                    .unwrap_or(1);

                // Check if it meets the threshold
                if verified_outputs_min_output_cardinality >= default_threshold {
                    println!("✅ Root {} build step has cardinality {} (threshold: {})",
                        self.interner.get_string(rdrv).unwrap_or("unknown"),
                        verified_outputs_min_output_cardinality, default_threshold);
                    true
                } else {
                    println!("❌ Root {} build step has cardinality {} (threshold: {})",
                        self.interner.get_string(rdrv).unwrap_or("unknown"),
                        verified_outputs_min_output_cardinality, default_threshold);
                    false
                }
            })
            .collect();

        if verified_roots.is_empty() {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - No roots had sufficient cardinality");
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