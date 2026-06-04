//! PyO3 bindings exposing the `lautr` Python module.
//!
//! Sign-only-relevant functions and verification-only functions are both
//! registered here so that the Python module surface is one cohesive thing.
//! Verification-only entries live behind the `verify` feature so that turning
//! it off produces a binary that doesn't depend on `lautr-verify` at all.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::path::Path;

use lautr_core::{constructive_trace, content_hash, derivation, thumbprint};

#[cfg(feature = "verify")]
mod trust_model_reasoner;

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_drv_path_from_aterm, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_nar_hash, m)?)?;
    m.add_function(wrap_pyfunction!(create_castore_entry, m)?)?;
    m.add_function(wrap_pyfunction!(compute_aterm_resolved_input_hash, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_thumbprint, m)?)?;

    #[cfg(feature = "verify")]
    register_verify(m)?;

    Ok(())
}

#[cfg(feature = "verify")]
fn register_verify(m: &Bound<'_, PyModule>) -> PyResult<()> {
    use crate::trust_model_reasoner::TrustModelReasoner;
    m.add_class::<TrustModelReasoner>()?;
    m.add_function(wrap_pyfunction!(fetch_signatures_from_cache, m)?)?;
    m.add_function(wrap_pyfunction!(verify_resolved_trace_signatures, m)?)?;
    Ok(())
}

#[pyfunction]
fn hash_upstream_placeholder(drv_path: &str, output_name: &str) -> PyResult<String> {
    derivation::hash_upstream_placeholder(drv_path, output_name)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[pyfunction]
fn calculate_drv_path_from_aterm(drv_name: &str, drv_aterm: &str) -> PyResult<String> {
    derivation::calculate_drv_path_from_aterm(drv_name, drv_aterm.as_bytes())
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[pyfunction]
fn calculate_nar_hash(path: &str) -> PyResult<String> {
    content_hash::calculate_nar_hash(Path::new(path))
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[pyfunction]
fn create_castore_entry(path: &str) -> PyResult<String> {
    content_hash::create_castore_entry(Path::new(path))
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
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

#[pyfunction]
fn ed25519_thumbprint(public_key: &[u8]) -> PyResult<String> {
    thumbprint::ed25519_thumbprint(public_key)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[cfg(feature = "verify")]
#[pyfunction]
fn fetch_signatures_from_cache(base_url: &str, input_hash: &str) -> PyResult<Option<Vec<u8>>> {
    lautr_verify::signature_verify::fetch_signatures_from_cache(base_url, input_hash)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[cfg(feature = "verify")]
#[pyfunction]
fn verify_resolved_trace_signatures(
    input_hash: &str,
    signatures: Vec<String>,
    trusted_keys: Vec<(String, Vec<u8>)>,
) -> PyResult<Vec<(String, String)>> {
    lautr_verify::signature_verify::verify_resolved_trace_signatures(
        input_hash,
        &signatures,
        &trusted_keys,
    )
    .map_err(|e| PyValueError::new_err(format!("{}", e)))
}
