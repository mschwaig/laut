//! Internal derivation summary, serialized as a `{drv_path: DrvJson}` map.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DrvJson {
    pub name: String,
    #[serde(rename = "inputDrvs")]
    pub input_drvs: BTreeMap<String, InputDrvRef>,
    pub outputs: BTreeMap<String, OutputRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputDrvRef {
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OutputRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Classify a derivation as fixed-output and/or content-addressed by looking at
/// the first output.
pub fn classify(outputs: &BTreeMap<String, OutputRef>) -> (bool, bool) {
    let first = outputs.values().next();
    let has_path = first.and_then(|o| o.path.as_ref()).is_some();
    let has_hash = first.and_then(|o| o.hash.as_ref()).is_some();
    // A declared content-address method with a concrete output path is fixed.
    let has_method = first.and_then(|o| o.method.as_ref()).is_some();
    let is_fixed_output = has_hash || (has_path && has_method);
    let is_content_addressed = !has_path && !has_hash;
    (is_fixed_output, is_content_addressed)
}
