use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use nix_compat::store_path;
use laut_compat::content_hash;
use nix_compat::derivation::calculate_derivation_path_from_aterm;
use std::collections::HashMap;
use std::path::Path;

mod constructive_trace;
mod string_interner;
mod trust_model_reasoner;
mod verifier;

#[cfg(test)]
mod type_confusion_test;

use trust_model_reasoner::TrustModelReasoner;

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {

    m.add_class::<TrustModelReasoner>()?;

    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_drv_path_from_aterm, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_nar_hash, m)?)?;
    m.add_function(wrap_pyfunction!(create_castore_entry, m)?)?;
    m.add_function(wrap_pyfunction!(compute_aterm_resolved_input_hash, m)?)?;

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

/// Compute the resolved drv path and resolved ATerm for an unresolved derivation.
///
/// `resolutions` maps unresolved input-derivation paths to output-name ->
/// content-hash-path maps. An empty `resolutions` (e.g. for a FOD or a
/// derivation with no input derivations) returns the input ATerm unchanged.
#[pyfunction]
fn compute_aterm_resolved_input_hash(
    drv_name: &str,
    drv_aterm: &[u8],
    resolutions: HashMap<String, HashMap<String, String>>,
) -> PyResult<(String, String)> {
    constructive_trace::compute_resolved_input_hash(drv_name, drv_aterm, &resolutions)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}
