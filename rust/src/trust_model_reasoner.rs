use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use datafrog::{Iteration, Relation, Variable};
use std::collections::HashMap;

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
    rdrvs_outputs_x_as_y: Variable<(usize,usize,usize)>,
}

#[pymethods]
impl TrustModelReasoner {
    #[new]
    fn new() -> Self {
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
        let rdrvs_outputs_x_as_y = fill_iteration.variable::<(usize,usize,usize)>("rdrvs_outputs_x_as_y");

        TrustModelReasoner {
            interner: StringInterner::new(),
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
            rdrvs_outputs_x_as_y,
        }
    }
    
    fn add_fod(&mut self, fod_to_add: &str, fod_hash_to_add: &str) -> Result<(), PyErr> {
        self.fods.extend(vec![(self.interner.intern(fod_to_add), self.interner.intern(fod_hash_to_add))]);
        self.udrvs.extend(vec![(self.interner.intern(fod_to_add))]);
        self.build_outputs.extend(vec![(self.interner.intern(fod_hash_to_add))]);

        Ok(())
    }
    
    fn add_unresolved_derivation(&mut self, udrv_to_add: &str, depends_on: Vec<String>, outputs: Vec<String>) -> Result<(), PyErr> {
        self.udrvs.extend(vec![(self.interner.intern(udrv_to_add))]);
        for item in depends_on.iter() {
            self.udrv_outputs.extend(vec![(self.interner.intern(item))]);
            self.udrvs_depends_on_x.extend(vec![(self.interner.intern(udrv_to_add), self.interner.intern(item))]);
        }
        for item in outputs.iter() {
            self.udrv_outputs.extend(vec![(self.interner.intern(item))]);
            self.udrvs_has_output_x.extend(vec![(self.interner.intern(udrv_to_add), self.interner.intern(item))]);
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

            self.udrvs_depends_on_x.extend(vec![(self.interner.intern(resolves_udrv), self.interner.intern(key))]);
            self.rdrvs_resolve_x_with_y.extend(vec![(self.interner.intern(with_rdrv), self.interner.intern(key), self.interner.intern(value))]);
        }

        Ok(())
    }
    
    fn add_build_output_claim(&mut self, from_resolved: &str, building_x_into_y: HashMap<String, String>) -> Result<(), PyErr> {
        self.rdrvs.extend(vec![(self.interner.intern(from_resolved))]);
        for (as_output, to_built) in &building_x_into_y {
            self.udrv_outputs.extend(vec![(self.interner.intern(as_output))]);
            self.build_outputs.extend(vec![(self.interner.intern(to_built))]);
            self.rdrvs_outputs_x_as_y.extend(vec![(self.interner.intern(from_resolved), self.interner.intern(to_built), self.interner.intern(as_output))]);
        }

        Ok(())
    }
    
    //#[pyfunction]
    //fn add_target(build_output, trust_model) -> Result<(), PyErr>  {
        // add to build output claim
    //    Ok(())
    //}
    
    //#[pyfunction]
    //fn add_treshold(tm_name, treshold, constituents) -> Result<(), PyErr> {
        // add to build output claim
    //    Ok(())
    //}

    fn compute_result(&mut self) -> Result<Vec<String>, PyErr> {

        while self.fill_iteration.changed() {
            // run empty loop for datalog to reach fixed point
        }

        // clone into relations so we can do stuff
        let fods_relation = self.fods.clone().complete();
        let build_outputs_relation = self.build_outputs.clone().complete();
        let udrvs_relation = self.udrvs.clone().complete();
        let udrv_outputs_relation = self.udrv_outputs.clone().complete();
        let udrvs_has_output_x_relation = self.udrvs_has_output_x.clone().complete();
        let udrvs_depends_on_x_relation = self.udrvs_depends_on_x.clone().complete();
        let rdrvs_relation = self.rdrvs.clone().complete();
        let rdrvs_resolves_x_relation = self.rdrvs_resolves_x.clone().complete();
        let rdrvs_resolve_x_with_y_relation = self.rdrvs_resolve_x_with_y.clone().complete();
        let rdrvs_outputs_x_as_y_relation = self.rdrvs_outputs_x_as_y.clone().complete();

        //
        // do some consistency checks
        //

        let mut root_candidates: Vec<usize> = Vec::new();
        let mut dependency_targets: Vec<usize> = Vec::new();

        for &(_, dep) in udrvs_depends_on_x_relation.iter() {
            dependency_targets.push(dep);
        }
        for &udrv in udrvs_relation.iter() {
            if !dependency_targets.contains(&udrv) {
                root_candidates.push(udrv);
            }
        }

        // (1) unresolved tree has one unique root
        if root_candidates.len() != 1 {
            println!("\n=== Verification Results ===\n");
            println!("❌ Could not find sufficient evidence for verification:");
            println!("  - Expected exactly one root derivation, found {}", root_candidates.len());
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

        // print outputs
        let mut root_outputs: Vec<String> = Vec::new();

        for &rdrv in &resolved_roots {
            let outputs: Vec<(usize, usize)> = rdrvs_outputs_x_as_y_relation.iter()
                .filter(|&(r, _, _)| *r == rdrv)
                .map(|&(_, output, name)| (output, name))
                .collect();

            for (output, name) in outputs {
                root_outputs.push(format!(
                    "Output {} of {} resolves to {}",
                    self.interner.get_string(name).unwrap_or("unknown"),
                    self.interner.get_string(rdrv).unwrap_or("unknown"),
                    self.interner.get_string(output).unwrap_or("unknown")
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