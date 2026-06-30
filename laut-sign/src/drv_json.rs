//! Subset of the `nix derivation show` JSON shape we care about.
//!
//! `nix derivation show --recursive <drv>` returns a `{drv_path: drv}` map;
//! each entry has at least `name`, `inputDrvs`, and `outputs`. We capture just
//! what the orchestrator needs and ignore everything else.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DrvJson {
    pub name: String,
    #[serde(rename = "inputDrvs")]
    pub input_drvs: BTreeMap<String, InputDrvRef>,
    pub outputs: BTreeMap<String, OutputRef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InputDrvRef {
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OutputRef {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
}

/// Classify a derivation as fixed-output and/or content-addressed by looking at
/// the first output. Mirrors `laut.nix.commands.get_derivation_type`.
pub fn classify(outputs: &BTreeMap<String, OutputRef>) -> (bool, bool) {
    let first = outputs.values().next();
    let has_path = first.and_then(|o| o.path.as_ref()).is_some();
    let has_hash = first.and_then(|o| o.hash.as_ref()).is_some();
    // Lix's nix derivation show omits the `hash` field on some FOD outputs
    // while still emitting `method` (e.g. "nar", "flat"). A non-CA
    // derivation with a declared output hash method is a FOD.
    let has_method = first.and_then(|o| o.method.as_ref()).is_some();
    let is_fixed_output = has_hash || (has_path && has_method);
    let is_content_addressed = !has_path && !has_hash;
    (is_fixed_output, is_content_addressed)
}
