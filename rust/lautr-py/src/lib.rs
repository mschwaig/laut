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

use lautr_core::{
    constructive_trace, content_hash, derivation, http_cache, keyfiles, nix_cmd, signing,
    store_path, thumbprint,
};

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
    m.add_function(wrap_pyfunction!(get_nix_path_input_hash, m)?)?;
    m.add_function(wrap_pyfunction!(parse_nix_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(nix_derivation_show, m)?)?;
    m.add_function(wrap_pyfunction!(nix_derivation_show_recursive, m)?)?;
    m.add_function(wrap_pyfunction!(nix_derivation_aterm, m)?)?;
    m.add_function(wrap_pyfunction!(nix_output_hash_from_disk, m)?)?;
    m.add_function(wrap_pyfunction!(parse_http_cache_url, m)?)?;
    m.add_function(wrap_pyfunction!(upload_signature, m)?)?;
    m.add_function(wrap_pyfunction!(create_trace_signature, m)?)?;

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
    m.add_function(wrap_pyfunction!(parse_nix_public_key, m)?)?;
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

/// Return the 32-character digest portion of a Nix store path.
#[pyfunction]
fn get_nix_path_input_hash(path: &str) -> PyResult<String> {
    store_path::extract_store_hash(path)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// Parse a Nix `name:base64` private-key file. Returns `(name, seed_bytes)`
/// where `seed_bytes` is the 32-byte ed25519 seed.
#[pyfunction]
fn parse_nix_private_key(path: &str) -> PyResult<(String, Vec<u8>)> {
    keyfiles::parse_private_key_file(Path::new(path))
        .map(|(name, seed)| (name, seed.to_vec()))
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// `nix derivation show <drv>` — returns raw JSON.
#[pyfunction]
fn nix_derivation_show(drv_path: &str) -> PyResult<String> {
    nix_cmd::derivation_show(drv_path).map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// `nix derivation show --recursive <drv>` — returns raw JSON.
#[pyfunction]
fn nix_derivation_show_recursive(drv_path: &str) -> PyResult<String> {
    nix_cmd::derivation_show_recursive(drv_path)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// `nix store cat <drv>` — returns the derivation's ATerm.
#[pyfunction]
fn nix_derivation_aterm(drv_path: &str) -> PyResult<String> {
    nix_cmd::derivation_aterm(drv_path).map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// `nix-store --query --hash <path>` — returns the trimmed `hashAlgo:hash` line.
#[pyfunction]
fn nix_output_hash_from_disk(out_path: &str) -> PyResult<String> {
    nix_cmd::output_hash_from_disk(out_path).map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// Validate an http(s) cache URL and return its canonical base form.
#[pyfunction]
fn parse_http_cache_url(store_url: &str) -> PyResult<String> {
    http_cache::parse_http_cache_url(store_url)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// Upload a JWS signature for `input_hash` to the HTTP cache at `store_url`,
/// merging with any concurrent uploads via ETag-based optimistic concurrency.
#[pyfunction]
fn upload_signature(store_url: &str, input_hash: &str, signature: &str) -> PyResult<()> {
    http_cache::upload_signature(store_url, input_hash, signature)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// Build and sign a laut trace JWS. Nested fields are passed as JSON strings
/// so the orchestrator (Python today) can shape them however it wants without
/// crossing PyO3 with a typed structure.
#[pyfunction]
#[pyo3(signature = (
    input_hash,
    debug_data_json,
    output_hashes_json,
    castore_outputs_json,
    rebuild_id,
    builder_nix_flavor,
    builder_nix_version,
    key_name,
    seed,
))]
fn create_trace_signature(
    input_hash: &str,
    debug_data_json: Option<&str>,
    output_hashes_json: &str,
    castore_outputs_json: &str,
    rebuild_id: u32,
    builder_nix_flavor: Option<&str>,
    builder_nix_version: Option<&str>,
    key_name: &str,
    seed: &[u8],
) -> PyResult<String> {
    let seed_arr: &[u8; 32] = seed
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("expected 32-byte seed, got {}", seed.len())))?;
    let debug_data = match debug_data_json {
        Some(s) => Some(parse_json(s, "debug_data")?),
        None => None,
    };
    let output_hashes = parse_json(output_hashes_json, "output_hashes")?;
    let castore_outputs = parse_json(castore_outputs_json, "castore_outputs")?;
    signing::create_trace_signature(
        input_hash,
        debug_data.as_ref(),
        &output_hashes,
        &castore_outputs,
        rebuild_id,
        builder_nix_flavor,
        builder_nix_version,
        key_name,
        seed_arr,
    )
    .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

fn parse_json(s: &str, field: &str) -> PyResult<serde_json::Value> {
    serde_json::from_str(s)
        .map_err(|e| PyValueError::new_err(format!("{}: invalid json: {}", field, e)))
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

/// Parse a Nix `name:base64` public-key file. Returns `(name, key_bytes)`
/// where `key_bytes` is the 32-byte ed25519 public key.
#[cfg(feature = "verify")]
#[pyfunction]
fn parse_nix_public_key(path: &str) -> PyResult<(String, Vec<u8>)> {
    lautr_verify::keyfiles::parse_public_key_file(Path::new(path))
        .map(|(name, key)| (name, key.to_vec()))
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}
