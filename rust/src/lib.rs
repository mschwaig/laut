use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use pyo3::exceptions::PyValueError;
use datafrog::{Iteration, Relation, Variable};
use nix_compat::store_path;
use nix_compat::derivation::calculate_derivation_path_from_aterm;

use pyo3::impl_::pymethods::IterBaseKind;

mod string_interner;
use string_interner::StringInterner;

use std::collections::HashMap;

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {

    m.add_class::<TrustModelReasoner>()?;

    m.add_function(wrap_pyfunction!(simple_datafrog_example, m)?)?;
    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_drv_path_from_aterm, m)?)?;

    Ok(())
}

// on a philosopical level I do not think we would need the ability to model
// resolving different outputs of the same derivation differently
// but practically thats exactly what legacy signatures end up allowing
// so I am not sure where we land there

#[pyclass(unsendable)]
struct TrustModelReasoner {
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
        self.fods.extend(vec![(self.interner.intern(fod_to_add),self.interner.intern(fod_hash_to_add))]);
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
        self.rdrvs_resolves_x.extend(vec![(self.interner.intern(with_rdrv),self.interner.intern(resolves_udrv))]);

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

    fn compute_result(&mut self, py: Python) -> Result<(), PyErr> {
    // compute build output variable
    
    // if this a 1:1 relationship unification is total, or we reject builds - no frankenbuilds
    // if it is a 1:n relationship unification is partial, and we have to do rewriting
    
    // in parctice we could make unification only total in terms of runtime closures
    // and have it be ok if it is not total for build time closures
        Ok(())
    }
}

// let's use a hash map to store all of the actual hashes :D
// insetad of mucking around with extracting the correct bits
// from the inputs and storing them efficiently
// this way we can feed in correctly formatted production data
// but also abbreviated test data
// and if we want, we can still do vaildation on the test data

// we could also be ultra lazy and say we take hashing seriously and if hashes collide then we consider things to be the same
// that way we can either do the hash function thing I just supposed, and assign increasing integers that way
// or we can just use the hash values raw, if that is faster
// we just cannot shorten them, because that makes us prone to collisions in the validation

// I also like datafrog, because I think we could get nice error messages out if it
// and maybe even a set of next actions if we are in the process of building stuff
// and already specified the unresolved graph

// it could tell us to fetch signatures
// or build stuff
// it could drive the build process

#[pyfunction]
fn hash_upstream_placeholder(drv_path: &str, output_name: &str) -> PyResult<String> {
    return store_path::hash_upstream_placeholder("/nix/store/", drv_path, output_name)
        .map_err(|err| PyErr::new::<pyo3::exceptions::PyValueError, _>(err));
 }

 #[pyfunction]
fn calculate_drv_path_from_aterm(drv_name: &str, drv_aterm: &str) -> PyResult<String> {
    let drv_path = calculate_derivation_path_from_aterm(drv_name, drv_aterm.as_bytes())
        .map_err(|e| PyValueError::new_err(format!("{:?}", e)))?;
        
    Ok(drv_path)
 }

#[pyfunction]
fn simple_datafrog_example() -> PyResult<usize> {

    let nodes: Relation<(u32,u32)> = vec![
     (1, 2), (3, 4)
    ].into();
    let edges: Relation<(u32,u32)> = vec![
     (1,2), (3,4), (2,3)
    ].into();

    let mut iteration = Iteration::new();

    let nodes_var = iteration.variable::<(u32,u32)>("nodes");
    let edges_var = iteration.variable::<(u32,u32)>("edges");

    nodes_var.insert(nodes.into());
    edges_var.insert(edges.into());

    while iteration.changed() {
        nodes_var.from_join(&nodes_var, &edges_var, |_b, &a, &c| (c,a));
    }

    let reachable: Relation<(u32,u32)> = nodes_var.complete();

    Ok(66)
}
