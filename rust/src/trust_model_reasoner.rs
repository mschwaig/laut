use pyo3::prelude::*;
use datafrog::{Iteration, Variable};
use std::collections::{HashMap, BTreeMap};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

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
    rdrvs_outputs_x_as_y_says_z: Variable<(usize,usize,usize,usize)>,
    trusted_keys: Variable<usize>,
    threshold: usize,
    // New relations to model output sets
    output_sets: Variable<usize>, // Each output set has a unique ID
    output_set_maps: Variable<(usize,usize,usize)>, // (output_set_id, udrv_output, build_output)
    rdrv_output_set_claim: Variable<(usize,usize,usize)>, // (rdrv, output_set_id, signing_key)
    // Effective cardinality tracking
    output_set_effective_cardinality: Variable<(usize,usize)>, // (output_set_id, effective_cardinality)
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
        let output_sets = fill_iteration.variable::<usize>("output_sets");
        let output_set_maps = fill_iteration.variable::<(usize,usize,usize)>("output_set_maps");
        let rdrv_output_set_claim = fill_iteration.variable::<(usize,usize,usize)>("rdrv_output_set_claim");
        let output_set_effective_cardinality = fill_iteration.variable::<(usize,usize)>("output_set_effective_cardinality");

        let mut interner = StringInterner::new();

        // Intern the trusted keys and populate the variable
        let interned_keys: Vec<usize> = trusted_keys.iter()
            .map(|key| interner.intern(key))
            .collect();

        trusted_keys_var.extend(interned_keys);

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
            output_sets,
            output_set_maps,
            rdrv_output_set_claim,
            output_set_effective_cardinality,
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

        // Create a canonical representation using BTreeMap for consistent ordering
        let canonical_map: BTreeMap<String, String> = building_x_into_y_says_z.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Hash the canonical representation
        let mut hasher = DefaultHasher::new();
        for (k, v) in &canonical_map {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }
        let output_set_hash = format!("output_set_{:x}", hasher.finish());
        let output_set_id = self.interner.intern(&output_set_hash);

        // Register this output set
        self.output_sets.extend(vec![output_set_id]);

        // Map this rdrv claim to the output set with the signing key
        self.rdrv_output_set_claim.extend(vec![(from_resolved_interned, output_set_id, interned_key)]);

        // Check if this is the first time we see this key - if so, create spawn debt
        // This can be determined later in datalog rules during compute_result

        // Populate the output set mappings
        for (as_output, to_built) in &building_x_into_y_says_z {
            let interned_output = self.interner.intern(as_output);
            let interned_built = self.interner.intern(to_built);

            self.udrv_outputs.extend(vec![interned_output]);
            self.build_outputs.extend(vec![interned_built]);

            // Map output_set -> (udrv_output, build_output)
            self.output_set_maps.extend(vec![(output_set_id, interned_output, interned_built)]);

            // Keep the original relation for now (can be removed later)
            self.rdrvs_outputs_x_as_y_says_z.extend(vec![(from_resolved_interned, interned_built, interned_output, interned_key)]);
        }

        Ok(())
    }
    

    fn compute_result(&mut self) -> Result<Vec<String>, PyErr> {

        // Force all data through the datafrog iteration pipeline
        // This ensures data moves from to_add -> recent -> stable
        while self.fill_iteration.changed() {
            // Empty loop for datalog to reach fixed point
        }

        // Complete all variables to relations
        let udrvs_depends_on_x_relation = self.udrvs_depends_on_x.clone().complete();

        let fods_relation = self.fods.clone().complete();
        let _build_outputs_relation = self.build_outputs.clone().complete();
        let udrvs_relation = self.udrvs.clone().complete();
        let _udrv_outputs_relation = self.udrv_outputs.clone().complete();
        let udrvs_has_output_x_relation = self.udrvs_has_output_x.clone().complete();
        let rdrvs_relation = self.rdrvs.clone().complete();
        let rdrvs_resolves_x_relation = self.rdrvs_resolves_x.clone().complete();
        let _rdrvs_resolve_x_with_y_relation = self.rdrvs_resolve_x_with_y.clone().complete();
        let rdrvs_outputs_x_as_y_says_z_relation = self.rdrvs_outputs_x_as_y_says_z.clone().complete();
        let rdrv_output_set_claim_relation = self.rdrv_output_set_claim.clone().complete();
        let trusted_keys_relation = self.trusted_keys.clone().complete();

        // Start a new iteration for effective cardinality computation
        let mut cardinality_iteration = Iteration::new();
        let effective_cardinality = cardinality_iteration.variable::<(usize, usize)>("effective_cardinality");

        // Initialize FOD outputs with infinite cardinality
        println!("\n=== FOD Initialization ===");
        for &(fod, _) in fods_relation.iter() {
            println!("FOD: {}", self.interner.get_string(fod).unwrap_or("unknown"));
            for &(udrv, output) in udrvs_has_output_x_relation.iter() {
                if udrv == fod {
                    effective_cardinality.extend(vec![(output, usize::MAX)]);
                    println!("  Initialized FOD output {} with ∞ cardinality",
                        self.interner.get_string(output).unwrap_or("unknown"));
                }
            }
        }

        // Create a map from output sets to their signature counts
        let mut output_set_signatures: HashMap<usize, usize> = HashMap::new();
        println!("\n=== Trusted Keys ===");
        for &key in trusted_keys_relation.iter() {
            println!("  {}", self.interner.get_string(key).unwrap_or("unknown"));
        }
        println!("\n=== Output Set Signatures ===");
        for &(rdrv, output_set, key) in rdrv_output_set_claim_relation.iter() {
            let is_trusted = trusted_keys_relation.iter().any(|&k| k == key);
            println!("  Output set {} signed by {} (trusted: {})",
                self.interner.get_string(output_set).unwrap_or("unknown"),
                self.interner.get_string(key).unwrap_or("unknown"),
                is_trusted);
            if is_trusted {
                *output_set_signatures.entry(output_set).or_insert(0) += 1;
            }
        }

        // Create a map from outputs to their signature counts via output sets
        let output_set_maps_relation = self.output_set_maps.clone().complete();
        let mut output_signatures: HashMap<usize, usize> = HashMap::new();
        println!("\n=== Output Signature Mapping ===");
        println!("Number of output sets with signatures: {}", output_set_signatures.len());
        println!("Number of output set mappings: {}", output_set_maps_relation.len());

        for &(output_set, udrv_output, build_output) in output_set_maps_relation.iter() {
            let output_set_str = self.interner.get_string(output_set).unwrap_or("unknown");
            let udrv_output_str = self.interner.get_string(udrv_output).unwrap_or("unknown");
            let build_output_str = self.interner.get_string(build_output).unwrap_or("unknown");

            if let Some(&sig_count) = output_set_signatures.get(&output_set) {
                // The udrv_output here is just the output name (e.g., "out")
                // We need to find all full paths that use this output name
                for &(udrv, full_output) in udrvs_has_output_x_relation.iter() {
                    let full_output_str = self.interner.get_string(full_output).unwrap_or("");
                    // Check if this output corresponds to our output name
                    if full_output_str.ends_with(&format!("${}", udrv_output_str)) {
                        output_signatures.insert(full_output, sig_count);
                        println!("  Output {} (name: {}, mapped to {}) from set {} -> {} signatures",
                            full_output_str, udrv_output_str, build_output_str, output_set_str, sig_count);
                    }
                }
            } else {
                println!("  Output {} (mapped to {}) from set {} -> NO signatures found!",
                    udrv_output_str, build_output_str, output_set_str);
            }
        }

        // Simplified cardinality computation
        println!("\n=== Cardinality Computation ===");
        let mut iteration_num = 0;
        while cardinality_iteration.changed() {
            iteration_num += 1;
            println!("\n--- Iteration {} ---", iteration_num);
            // Create cardinality map for lookups
            let cardinality_map: HashMap<usize, usize> = effective_cardinality.recent.borrow()
                .iter()
                .chain(effective_cardinality.stable.borrow().iter().flat_map(|batch| batch.iter()))
                .map(|&(output, card)| (output, card))
                .collect();

            // Check each output to see if it needs cardinality computed
            for &(udrv, output) in udrvs_has_output_x_relation.iter() {
                // Skip if this output already has cardinality
                if cardinality_map.contains_key(&output) {
                    continue;
                }

                let udrv_str = self.interner.get_string(udrv).unwrap_or("unknown");
                let output_str = self.interner.get_string(output).unwrap_or("unknown");
                println!("Checking output {} of udrv {}", output_str, udrv_str);

                // Find min cardinality of all dependencies
                let mut min_dep_cardinality = usize::MAX;
                let mut all_deps_have_cardinality = true;
                let mut dep_count = 0;

                for &(dep_udrv, dep_output) in udrvs_depends_on_x_relation.iter() {
                    if dep_udrv == udrv {
                        dep_count += 1;
                        let dep_output_str = self.interner.get_string(dep_output).unwrap_or("unknown");
                        if let Some(&card) = cardinality_map.get(&dep_output) {
                            println!("  Dependency {} has cardinality {}", dep_output_str, card);
                            min_dep_cardinality = min_dep_cardinality.min(card);
                        } else {
                            println!("  Dependency {} has NO cardinality yet", dep_output_str);
                            all_deps_have_cardinality = false;
                            break;
                        }
                    }
                }

                if dep_count == 0 {
                    println!("  No dependencies found");
                }

                // If all dependencies have cardinality (or no dependencies), compute output cardinality
                if all_deps_have_cardinality {
                    // Check if this output belongs to a FOD by checking if it's already marked with infinite cardinality
                    // in the cardinality_map (FODs are initialized with infinite cardinality)
                    let is_fod_output = cardinality_map.get(&output).map_or(false, |&c| c == usize::MAX);

                    let final_cardinality = if is_fod_output {
                        // FOD outputs always have infinite cardinality (trusted by content hash)
                        usize::MAX
                    } else {
                        // Regular outputs use signature count and dependency cardinality
                        let sig_count = output_signatures.get(&output).copied().unwrap_or(0);
                        if dep_count == 0 {
                            // For nodes with no dependencies, cardinality is just the signature count
                            sig_count
                        } else {
                            min_dep_cardinality.min(sig_count)
                        }
                    };

                    effective_cardinality.extend(vec![(output, final_cardinality)]);
                    let sig_count = output_signatures.get(&output).copied().unwrap_or(0);
                    println!("  Output {} -> cardinality {} (deps: {}, sigs: {}, is_fod: {})",
                        output_str,
                        if final_cardinality == usize::MAX { "∞".to_string() } else { final_cardinality.to_string() },
                        if min_dep_cardinality == usize::MAX { "∞".to_string() } else { min_dep_cardinality.to_string() },
                        sig_count,
                        is_fod_output);
                }
            }
        }

        //
        // do some consistency checks
        //

        let mut root_candidates: Vec<usize> = Vec::new();
        let mut dependency_targets: Vec<usize> = Vec::new();

        for &(_, dep) in udrvs_depends_on_x_relation.iter() {
            dependency_targets.push(dep);
        }

        // Check which udrvs have outputs that are dependency targets
        for &udrv in udrvs_relation.iter() {
            let mut is_dependency = false;

            // Check all outputs of this udrv to see if any are dependency targets
            for &(u, output) in udrvs_has_output_x_relation.iter() {
                if u == udrv {
                    if dependency_targets.contains(&output) {
                        is_dependency = true;
                        break;
                    }
                }
            }

            if !is_dependency {
                // Check if this is a FOD - we don't want FODs as root candidates
                let is_fod = fods_relation.iter().any(|&(fod, _)| fod == udrv);
                if !is_fod {
                    root_candidates.push(udrv);
                }
            }
        }

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

        // (1) all leaves are fods
        // TODO: all fods are leaves
        let leaf_derivations: Vec<usize> = udrvs_relation.iter()
            .filter(|&&udrv| {
                // Count outgoing dependencies for this derivation
                udrvs_depends_on_x_relation.iter()
                    .filter(|&&(d, _)| d == udrv)
                    .count() == 0
            })
            .cloned()
            .collect();
        for &leaf in &leaf_derivations {
            let is_fod = fods_relation.iter().any(|&(fod, _)| fod == leaf);
            if !is_fod {
                println!("\n=== Verification Results ===\n");
                println!("❌ Could not find sufficient evidence for verification:");
                println!("  - Leaf derivation {} is not a fixed-output derivation", self.interner.get_string(leaf).unwrap_or("unknown"));
                return Ok(Vec::new());
            }
        }

        let resolved_roots: Vec<usize> = rdrvs_resolves_x_relation.iter()
            .filter(|&(_, udrv)| *udrv == root_derivation)
            .map(|&(rdrv, _)| rdrv)
            .collect();
        if resolved_roots.is_empty() {
            // Root was not resolved, find out what evidence is missing
            // TODO: do this better
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - Root derivation {} was not resolved. Missing evidence.", self.interner.get_string(root_derivation).unwrap_or("unknown"));
            return Ok(Vec::new());
        }

        // No longer needed - using effective cardinality instead of checking all keys

        // Complete the cardinality computation and get the results
        let effective_cardinality_relation = effective_cardinality.complete();

        // Effective cardinality is now complete

        // Track which resolved derivations have enough effective cardinality at the root
        let mut verified_roots: Vec<usize> = Vec::new();

        for &rdrv in &resolved_roots {
            // Find the root's outputs and check their effective cardinality
            let udrv = rdrvs_resolves_x_relation.iter()
                .find(|&&(r, _)| r == rdrv)
                .map(|&(_, u)| u)
                .unwrap();

            let mut max_cardinality = 0;

            // Check all outputs of the root udrv
            for &(u, output) in udrvs_has_output_x_relation.iter() {
                if u == udrv {
                    for &(o, cardinality) in effective_cardinality_relation.iter() {
                        if o == output {
                            max_cardinality = max_cardinality.max(cardinality);
                            // Found matching output with cardinality
                        }
                    }
                }
            }

            if max_cardinality >= self.threshold {
                verified_roots.push(rdrv);
                println!("✅ Root {} verified with effective cardinality {} (threshold: {})",
                    self.interner.get_string(rdrv).unwrap_or("unknown"),
                    max_cardinality,
                    self.threshold);
            } else {
                println!("❌ Root {} only has effective cardinality {} (threshold: {})",
                    self.interner.get_string(rdrv).unwrap_or("unknown"),
                    max_cardinality,
                    self.threshold);
            }
        }

        if verified_roots.is_empty() {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - No roots had effective cardinality >= {}", self.threshold);
            return Ok(Vec::new());
        }

        // Use verified_roots instead of resolved_roots from here on
        let resolved_roots = verified_roots;

        // print outputs
        let mut root_outputs: Vec<String> = Vec::new();

        for &rdrv in &resolved_roots {
            let outputs: Vec<(usize, usize, usize)> = rdrvs_outputs_x_as_y_says_z_relation.iter()
                .filter(|&(r, _, _, _)| *r == rdrv)
                .map(|&(_, output, name, key)| (output, name, key))
                .collect();

            for (output, name, key) in outputs {
                root_outputs.push(format!(
                    "Output {} of {} resolves to {} (signed by {})",
                    self.interner.get_string(name).unwrap_or("unknown"),
                    self.interner.get_string(rdrv).unwrap_or("unknown"),
                    self.interner.get_string(output).unwrap_or("unknown"),
                    self.interner.get_string(key).unwrap_or("unknown")
                ));
            }
        }

        println!("\n=== Verification Results ===\n");

        let udrvs_count = udrvs_relation.len();
        let fods_count = fods_relation.len();
        let rdrvs_count = rdrvs_relation.len();

        let resolvable_count = udrvs_count - fods_count;

        println!("Build consists of {} unresolved derivations", udrvs_count);
        println!("with {} fixed-output derivations as leaves", fods_count);

        if resolvable_count > 0 {
            println!("Resolved {}/{} derivations via signatures",
                     rdrvs_count, resolvable_count);
        }

        println!("\nVerification status:");
        println!("✅ The root derivation [{}] was successfully resolved to:",
                 self.interner.get_string(root_derivation).unwrap_or("unknown"));

        for output in &root_outputs {
            println!("  - {}", output);
        }

        if !resolved_roots.is_empty() {
            println!("\nResolved via:");
            for &rdrv in &resolved_roots {
                println!("  - {}", self.interner.get_string(rdrv).unwrap_or("unknown"));
            }
        }

        let resolved_root_strings: Vec<String> = resolved_roots
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