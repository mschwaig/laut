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

#[pymodule]
fn lautr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_upstream_placeholder, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_drv_path_from_aterm, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_nar_hash, m)?)?;
    m.add_function(wrap_pyfunction!(create_castore_entry, m)?)?;
    m.add_function(wrap_pyfunction!(compute_aterm_resolved_input_hash, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_thumbprint, m)?)?;
    m.add_function(wrap_pyfunction!(get_nix_path_input_hash, m)?)?;
    m.add_function(wrap_pyfunction!(nix_derivation_show, m)?)?;
    m.add_function(wrap_pyfunction!(nix_derivation_show_recursive, m)?)?;
    m.add_function(wrap_pyfunction!(nix_derivation_aterm, m)?)?;
    m.add_function(wrap_pyfunction!(nix_output_hash_from_disk, m)?)?;
    m.add_function(wrap_pyfunction!(upload_signature, m)?)?;
    m.add_function(wrap_pyfunction!(create_trace_signature, m)?)?;

    #[cfg(feature = "verify")]
    register_verify(m)?;

    Ok(())
}

#[cfg(feature = "verify")]
fn register_verify(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_nix_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(verify_tree, m)?)?;
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

/// Upload a JWS signature for `input_hash` to the HTTP cache at `store_url`,
/// merging with any concurrent uploads via ETag-based optimistic concurrency.
#[pyfunction]
fn upload_signature(store_url: &str, input_hash: &str, signature: &str) -> PyResult<()> {
    http_cache::upload_signature(store_url, input_hash, signature)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

/// Parse the signing key file (via snix) and build+sign a laut trace JWS.
///
/// Seed bytes never cross PyO3: snix validates the keypair and produces the
/// `ed25519_dalek::SigningKey`, signing happens here, and Python only sees
/// the resulting JWS string.
#[pyfunction]
#[pyo3(signature = (
    input_hash,
    debug_data_json,
    output_hashes_json,
    castore_outputs_json,
    rebuild_id,
    builder_nix_flavor,
    builder_nix_version,
    secret_key_file,
))]
fn create_trace_signature(
    input_hash: &str,
    debug_data_json: Option<&str>,
    output_hashes_json: &str,
    castore_outputs_json: &str,
    rebuild_id: u32,
    builder_nix_flavor: Option<&str>,
    builder_nix_version: Option<&str>,
    secret_key_file: &str,
) -> PyResult<String> {
    let (key_name, signing_key) = keyfiles::parse_private_key_file(Path::new(secret_key_file))
        .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
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
        &key_name,
        &signing_key,
    )
    .map_err(|e| PyValueError::new_err(format!("{}", e)))
}

fn parse_json(s: &str, field: &str) -> PyResult<serde_json::Value> {
    serde_json::from_str(s)
        .map_err(|e| PyValueError::new_err(format!("{}: invalid json: {}", field, e)))
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

/// Verify a derivation tree end-to-end. Returns a list of description strings
/// (one per verified candidate output map). Empty list = verification failed.
///
/// `debug_preimage_corpus` opts into hash-divergence debugging: when set, the
/// verifier lists the given cache's `/traces/`, parses any debug preimages it
/// finds (permissive — unverified signatures still contribute), and renders a
/// structural diff against locally-computed preimages whenever a `ct_input_hash`
/// lookup misses. The flag is intended for test/dev environments; production
/// caches won't list and don't carry preimages.
#[cfg(feature = "verify")]
#[pyfunction]
#[pyo3(signature = (
    drv_path,
    cache_urls,
    trusted_keys,
    allow_ia,
    debug_preimage_corpus = None,
    debug_out_dir = None,
))]
fn verify_tree(
    drv_path: &str,
    cache_urls: Vec<String>,
    trusted_keys: Vec<(String, Vec<u8>)>,
    allow_ia: bool,
    debug_preimage_corpus: Option<String>,
    debug_out_dir: Option<String>,
) -> PyResult<Vec<String>> {
    use lautr_verify::debug::{build_corpus_from_cache_listing, DebugProbe, DifftProbe, NullProbe};

    let probe: Box<dyn DebugProbe> = match debug_preimage_corpus {
        Some(corpus_url) => {
            let index = build_corpus_from_cache_listing(&corpus_url)
                .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
            let out_dir = debug_out_dir
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let difft = DifftProbe::new(index, out_dir)
                .map_err(|e| PyValueError::new_err(format!("debug dir: {}", e)))?;
            Box::new(difft)
        }
        None => Box::new(NullProbe),
    };

    let cfg = lautr_verify::orchestrator::Config {
        root_drv_path: drv_path.to_owned(),
        cache_urls,
        trusted_keys,
        allow_ia,
        debug_probe: probe,
    };
    let mut orch =
        lautr_verify::orchestrator::Orchestrator::new(lautr_verify::backend::RealBackend, cfg)
            .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
    orch.verify()
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}
