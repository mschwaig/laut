//! Sign-side orchestration: given a resolved derivation path and its
//! post-build out-paths, build the trace JWS and (optionally) upload it.
//!
//! Mirrors the pipeline phases used by [`crate::drv_json`] and the verify-side
//! [`laut-verify::orchestrator`]: a small entry surface declared here, with
//! the JWS payload assembly and the `$NIX_CONFIG` parsing factored into
//! [`jws`] and [`nix_version`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde_json::{Value, json};

use crate::content_hash;
use crate::derivation;
use crate::drv_json::{self, DrvJson};
use crate::http_cache;
use crate::keyfiles;
use crate::nix_cmd;
use crate::store_path;

pub mod jws;
pub mod nix_version;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("nix command: {0}")]
    NixCmd(#[from] nix_cmd::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store path: {0}")]
    StorePath(#[from] store_path::Error),
    #[error("keyfile: {0}")]
    Keyfile(#[from] keyfiles::Error),
    #[error("content hash: {0}")]
    ContentHash(#[from] content_hash::Error),
    #[error("jws: {0}")]
    Jws(#[from] jws::Error),
    #[error("derivation: {0}")]
    Derivation(#[from] derivation::Error),
    #[error("upload: {0}")]
    Upload(#[from] http_cache::Error),
    #[error("derivation {0:?} not found in `nix derivation show` output")]
    DrvNotFound(String),
    #[error("derivation JSON missing field {0:?}")]
    MissingField(&'static str),
    #[error("out-path {path:?} is unmatched and has no `path` set after assignment")]
    UnassignedOutput { path: String },
}

pub struct SignConfig {
    pub drv_path: String,
    pub out_paths: Vec<String>,
    pub secret_key_file: PathBuf,
    /// When true, embed the resolved drv name, path, computed path, and ATerm
    /// preimage under `payload.in.debug`. Test/dev only — production signers
    /// should leave this off so preimages never enter shared caches.
    pub include_preimage: bool,
}

/// Build and sign a trace JWS. Returns `None` when the post-build hook fires
/// on the unresolved derivation (input_drvs non-empty), on a FOD, or on an
/// input-addressed derivation — those are out-of-scope, not errors.
pub fn sign(cfg: &SignConfig) -> Result<Option<(String, String)>, Error> {
    let drv_show_raw = nix_cmd::derivation_show(&cfg.drv_path)?;

    let drvs: BTreeMap<String, DrvJson> = serde_json::from_str(&drv_show_raw)?;
    let drv = drvs
        .get(&cfg.drv_path)
        .ok_or_else(|| Error::DrvNotFound(cfg.drv_path.clone()))?;

    if !drv.input_drvs.is_empty() {
        // nix calls the post-build hook twice: once on the unresolved drv and
        // once on the resolved one. Bail on the unresolved invocation.
        return Ok(None);
    }

    let (is_fixed_output, is_content_addressed) = drv_json::classify(&drv.outputs);
    if is_fixed_output {
        // FODs: out of scope (future work, separate guarantees).
        return Ok(None);
    }
    if !is_content_addressed {
        // Input-addressed: out of scope.
        return Ok(None);
    }
    let drv_name = drv.name.clone();
    let output_names: Vec<String> = drv.outputs.keys().cloned().collect();

    // Second parse to preserve fields like `hashAlgo` / `method` on each
    // output entry that the narrow `DrvJson` shape drops.
    let raw: Value = serde_json::from_str(&drv_show_raw)?;
    let mut output_hashes_map = raw
        .get(&cfg.drv_path)
        .and_then(|d| d.get("outputs"))
        .and_then(|o| o.as_object())
        .cloned()
        .ok_or(Error::MissingField("outputs"))?;

    for path in &cfg.out_paths {
        let matched = output_names.iter().find(|name| {
            path.ends_with(&format!("-{}", name))
                || (name.as_str() == "out"
                    && !output_names
                        .iter()
                        .any(|n| path.ends_with(&format!("-{}", n))))
        });
        if let Some(name) = matched {
            let hash = nix_cmd::output_hash_from_disk(path)?;
            let entry = output_hashes_map
                .get_mut(name)
                .and_then(|v| v.as_object_mut())
                .ok_or(Error::MissingField("outputs[name]"))?;
            entry.insert("path".into(), Value::String(path.clone()));
            entry.insert("hash".into(), Value::String(hash));
        }
    }

    let aterm = nix_cmd::derivation_aterm(&cfg.drv_path)?;
    let computed_drv_path =
        derivation::calculate_drv_path_from_aterm(&drv_name, aterm.as_bytes())?;

    let debug_data = if cfg.include_preimage {
        Some(json!({
            "drv_name": drv_name,
            "rdrv_path": cfg.drv_path,
            "rdrv_computed_path": computed_drv_path,
            "rdrv_aterm_ca_preimage": aterm,
        }))
    } else {
        None
    };

    let mut castore_outputs = serde_json::Map::new();
    for (name, entry) in output_hashes_map.iter() {
        let path = entry
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::UnassignedOutput {
                path: name.clone(),
            })?;
        let encoded = content_hash::create_castore_entry(Path::new(path))?;
        castore_outputs.insert(name.clone(), Value::String(encoded));
    }

    let mut buf = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut buf);
    let rebuild_id = u32::from_le_bytes(buf);

    let (flavor, version) = std::env::var("NIX_CONFIG")
        .ok()
        .map(|s| nix_version::extract_nix_version_from_nix_config(&s))
        .unwrap_or((None, None));

    let input_hash = store_path::extract_store_hash(&cfg.drv_path)?;
    let (key_name, signing_key) = keyfiles::parse_private_key_file(&cfg.secret_key_file)?;

    let jws_token = jws::create_trace_signature(
        &input_hash,
        debug_data.as_ref(),
        &Value::Object(output_hashes_map),
        &Value::Object(castore_outputs),
        rebuild_id,
        flavor.as_deref(),
        version.as_deref(),
        &key_name,
        &signing_key,
    )?;

    Ok(Some((input_hash, jws_token)))
}

/// Sign and POST to the given HTTP cache. Silently no-ops on the same
/// "out of scope" cases as [`sign`].
pub fn sign_and_upload(cfg: &SignConfig, to: &str) -> Result<(), Error> {
    if let Some((input_hash, jws_token)) = sign(cfg)? {
        http_cache::upload_signature(to, &input_hash, &jws_token)?;
    }
    Ok(())
}
