use pyo3::prelude::*;
use datafrog::{Iteration, Relation};
use nix_compat::store_path;

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(simple_datafrog_example, m)?)?;
    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;
    Ok(())
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
fn setup() -> PyResult<usize> {
}

#[pyfunction]
fn add_fod() -> PyResult<usize> {
    // add to FOD relation
}

#[pyfunction]
fn add_unresolved_derivation() -> PyResult<usize> {
    // add to unresolved derivation relation
}

7#[pyfunction]
fn add_resolved_derivation(resolves, with, resolving x with y) -> PyResult<usize> {
   // add to resolved derivation relation
}


fn add_build_output_claim(resolved, built) -> PyResult<usize> {
    // add to build output claim
}

#[pyfunction]
fn add_target(build_output, trust_model) -> PyResult<usize> {
    // add to build output claim
}

#[pyfunction]
fn add_treshold(tm_name, treshold, constituents) -> PyResult<usize> {
    // add to build output claim
}

#[pyfunction]
fn compute_result() -> PyResult<usize> {
// compute build output variable

// if this a 1:1 relationship unification is total, or we reject builds - no frankenbuilds
// if it is a 1:n relationship unification is partial, and we have to do rewriting

// in parctice we could make unification only total in terms of runtime closures
// and have it be ok if it is not total for build time closures
}

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
