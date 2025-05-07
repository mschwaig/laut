use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use datafrog::{Iteration, Relation};
use nix_compat::store_path;

use pyo3::impl_::pymethods::IterBaseKind;

mod string_interner;
use string_interner::StringInterner;

use std::collections::HashMap;

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {

    m.add_class::<TrustModelReasoner>()?;

    m.add_function(wrap_pyfunction!(simple_datafrog_example, m)?)?;
    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;

    Ok(())
}

#[pyclass]
struct TrustModelReasoner {
    interner: StringInterner,
}

#[pymethods]
impl TrustModelReasoner {
    #[new]
    fn new() -> Self {
        TrustModelReasoner {
            interner: StringInterner::new(),
        }
    }
    
    fn add_fod(&mut self) -> Result<(), PyErr> {
        // add to FOD relation
        Ok(())
    }
    
    fn add_unresolved_derivation(&mut self, py: Python, to_add_udrv: &str, depends_on: Vec<String>) -> Result<(), PyErr> {
        // Extract strings from PyList as needed
        for item in depends_on.iter() {
            // Use dep_str
        }
        // add to unresolved derivation relation
        Ok(())
    }
    
    fn add_resolved_derivation(&mut self, py: Python, resolves_udrv: &str, with_rdrv: &str, resolving_x_with_y: HashMap<String, String>) -> Result<(), PyErr> {
        // Extract tuples from PyList as needed
        for (key, value) in &resolving_x_with_y {
            // Use key and value
        }
       // add to resolved derivation relation
       Ok(())
    }
    
    fn add_build_output_claim(&mut self, py: Python, from_resolved: &str, to_built: &str) -> Result<(), PyErr> {
        // add to build output claim
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
