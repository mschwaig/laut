//! Sign-side orchestration: given a resolved derivation path and its
//! post-build out-paths, build the trace JWS and (optionally) upload it.
//!
//! Mirrors the pipeline phases used by [`crate::drv_json`] and the verify-side
//! [`laut-verify::orchestrator`]: a small entry surface declared here, with
//! the JWS payload assembly and the `$NIX_CONFIG` parsing factored into
//! [`jws`] and [`nix_version`].

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use laut_compat::content_hash::format_nar_hash;
use nix_compat::nixhash::NixHash;
use nix_compat::store_path::StorePath;
use rand::RngCore;
use serde_json::{Value, json};

use crate::constructive_trace;
use crate::content_hash;
use crate::derivation;
use crate::drv_json::{self, DrvJson};
use crate::http_cache;
use crate::ia_closure;
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
    #[error("ia closure: {0}")]
    IaClosure(#[from] ia_closure::Error),
    #[error("constructive trace: {0}")]
    ConstructiveTrace(#[from] constructive_trace::Error),
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

    let (is_fixed_output, is_content_addressed) = drv_json::classify(&drv.outputs);
    if is_fixed_output {
        // FODs: out of scope (future work, separate guarantees).
        return Ok(None);
    }
    if is_content_addressed && !drv.input_drvs.is_empty() {
        // CA: nix fires the post-build hook twice (once on the unresolved drv
        // with input placeholders, once on the resolved drv with input
        // placeholders substituted). Only act on the resolved invocation.
        // IA has no resolution step, so we run the IA branch even when
        // `input_drvs` is populated.
        return Ok(None);
    }
    let from_ia = !is_content_addressed;
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

    let (input_hash, castore_outputs, debug_data) = if from_ia {
        sign_ia_outputs(
            cfg,
            drv,
            &drv_name,
            &computed_drv_path,
            &aterm,
            &mut output_hashes_map,
        )?
    } else {
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
        let input_hash = store_path::extract_store_hash(&cfg.drv_path)?;
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
        (input_hash, Value::Object(castore_outputs), debug_data)
    };

    let mut buf = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut buf);
    let rebuild_id = u32::from_le_bytes(buf);

    let (flavor, version) = std::env::var("NIX_CONFIG")
        .ok()
        .map(|s| nix_version::extract_nix_version_from_nix_config(&s))
        .unwrap_or((None, None));

    let (key_name, signing_key) = keyfiles::parse_private_key_file(&cfg.secret_key_file)?;

    let jws_token = jws::create_trace_signature(
        &input_hash,
        debug_data.as_ref(),
        &Value::Object(output_hashes_map),
        &castore_outputs,
        rebuild_id,
        flavor.as_deref(),
        version.as_deref(),
        &key_name,
        &signing_key,
        from_ia,
    )?;

    Ok(Some((input_hash, jws_token)))
}

/// IA branch of [`sign`]: walks the runtime closure of every requested out-path,
/// substitutes synthetic CA paths into `output_hashes_map`, computes the
/// CA-equivalent drv path via [`constructive_trace::compute_resolved_input_hash_ia`],
/// and returns the trio the caller plugs into the JWS.
///
/// `output_hashes_map[name].hash` is overwritten with the SHA256 NAR hash of
/// the pass-2 rewritten content so the verifier can recompute and compare
/// symmetrically — see `ia_closure::Walker::root_result`.
fn sign_ia_outputs(
    cfg: &SignConfig,
    drv: &DrvJson,
    drv_name: &str,
    computed_ia_drv_path: &str,
    ia_aterm: &str,
    output_hashes_map: &mut serde_json::Map<String, Value>,
) -> Result<(String, Value, Option<Value>), Error> {
    let mut walker = ia_closure::Walker::new();

    // pass-1 + pass-2 for each requested output: synthetic CA path + castore
    // Entry of the rewritten content + NAR hash. The walker memoizes closure
    // nodes across roots.
    struct Synthetic {
        ia_path: String,
        synthetic_ca: StorePath<String>,
        castore_entry: String,
        nar_hash: NixHash,
    }
    let mut name_to_synthetic: HashMap<String, Synthetic> = HashMap::new();
    for (name, entry) in output_hashes_map.iter() {
        let ia_path = entry
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::UnassignedOutput {
                path: name.clone(),
            })?;
        let result = walker.root_result(ia_path)?;
        name_to_synthetic.insert(
            name.clone(),
            Synthetic {
                ia_path: ia_path.to_owned(),
                synthetic_ca: result.synthetic_ca_path,
                castore_entry: result.castore_entry_base64,
                nar_hash: result.nar_hash,
            },
        );
    }

    // Build the IA→synthetic-CA substitution map covering this drv's outputs
    // and every input drv's outputs that the ATerm references. Also collect
    // the input drvs' synthetic CA paths to fold into inputSrcs.
    let mut substitutions: HashMap<String, String> = HashMap::new();
    let mut input_sources: Vec<StorePath<String>> = Vec::new();

    for (input_drv_path, input_drv_ref) in &drv.input_drvs {
        let input_show_raw = nix_cmd::derivation_show(input_drv_path)?;
        let input_drvs: BTreeMap<String, DrvJson> = serde_json::from_str(&input_show_raw)?;
        let input_drv = input_drvs
            .get(input_drv_path)
            .ok_or_else(|| Error::DrvNotFound(input_drv_path.clone()))?;
        let (input_is_fod, _) = drv_json::classify(&input_drv.outputs);
        for output_name in &input_drv_ref.outputs {
            let ia_path = input_drv
                .outputs
                .get(output_name)
                .and_then(|o| o.path.clone())
                .ok_or(Error::MissingField("input_drv outputs[name].path"))?;
            // FOD outputs are already content-addressed by their declared
            // hash — their `synthetic CA path` is just themselves. We must
            // NOT walk them via pass-1 (which would derive a NAR-mode CA
            // path that diverges from the FOD's actual flat/declared scheme).
            // The verifier mirrors this in its FOD branch.
            let synthetic_abs = if input_is_fod {
                ia_path.clone()
            } else {
                walker.synthetic_ca_path(&ia_path)?.to_absolute_path()
            };
            let synthetic_sp = StorePath::<String>::from_absolute_path(synthetic_abs.as_bytes())
                .map_err(|e| Error::StorePath(store_path::Error::Parse {
                    path: synthetic_abs.clone(),
                    source: e,
                }))?;
            substitutions.insert(ia_path, synthetic_abs);
            input_sources.push(synthetic_sp);
        }
    }

    for syn in name_to_synthetic.values() {
        substitutions.insert(syn.ia_path.clone(), syn.synthetic_ca.to_absolute_path());
    }

    // Synthetic CA-equivalent drv path → cache key for this trace.
    let (synthetic_drv_path, rewritten_aterm) = constructive_trace::compute_resolved_input_hash_ia(
        drv_name,
        ia_aterm.as_bytes(),
        input_sources,
        &substitutions,
    )?;
    let input_hash = store_path::extract_store_hash(&synthetic_drv_path)?;

    // Swap `path` and `hash` in payload.out.nix for the synthetic CA path and
    // the NAR hash of the rewritten content. The result has the "pretend-CA"
    // shape end-to-end: the verifier reads these as the values it should
    // independently recompute from its local store via the same closure walk.
    let mut castore_outputs = serde_json::Map::new();
    for (name, entry) in output_hashes_map.iter_mut() {
        let syn = name_to_synthetic
            .get(name)
            .ok_or(Error::MissingField("ia synthetic for output"))?;
        let entry_obj = entry
            .as_object_mut()
            .ok_or(Error::MissingField("outputs[name]"))?;
        entry_obj.insert(
            "path".into(),
            Value::String(syn.synthetic_ca.to_absolute_path()),
        );
        entry_obj.insert("hash".into(), Value::String(format_nar_hash(&syn.nar_hash)));
        castore_outputs.insert(name.clone(), Value::String(syn.castore_entry.clone()));
    }

    let debug_data = if cfg.include_preimage {
        Some(json!({
            "drv_name": drv_name,
            "rdrv_path": cfg.drv_path,
            "rdrv_computed_path": computed_ia_drv_path,
            "rdrv_aterm_ca_preimage": rewritten_aterm,
            "ia": true,
        }))
    } else {
        None
    };

    Ok((input_hash, Value::Object(castore_outputs), debug_data))
}

/// Sign and POST to the given HTTP cache. Silently no-ops on the same
/// "out of scope" cases as [`sign`].
pub fn sign_and_upload(cfg: &SignConfig, to: &str) -> Result<(), Error> {
    if let Some((input_hash, jws_token)) = sign(cfg)? {
        http_cache::upload_signature(to, &input_hash, &jws_token)?;
    }
    Ok(())
}
