use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use datafrog::{Iteration, Relation, Variable};
use nix_compat::store_path;
use laut_compat::content_hash;
use nix_compat::derivation::calculate_derivation_path_from_aterm;
use std::path::Path;

mod string_interner;
mod trust_model_reasoner;

use string_interner::StringInterner;
use trust_model_reasoner::TrustModelReasoner;

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {

    m.add_class::<TrustModelReasoner>()?;

    m.add_function(wrap_pyfunction!(simple_datafrog_example, m)?)?;
    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_drv_path_from_aterm, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_nar_hash, m)?)?;
    m.add_function(wrap_pyfunction!(create_castore_entry, m)?)?;

    Ok(())
}

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
 fn calculate_nar_hash(path: &str) -> PyResult<String> {
    let path = Path::new(path);
    let (hash, _size) = content_hash::calculate_nar_hash(path, None)
        .map_err(|err| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", err)))?;
    Ok(content_hash::format_nar_hash(&hash))
 }

#[pyfunction]
 fn create_castore_entry(path: &str) -> PyResult<String> {
    let path = Path::new(path);
    let result = content_hash::create_castore_entry(path)
        .map_err(|err| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", err)))?;
    Ok(result)
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

    let _reachable: Relation<(u32,u32)> = nodes_var.complete();

    Ok(66)
}