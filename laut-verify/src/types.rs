//! Domain types for the verification orchestrator.
//!
//! Mirrors the Python `nix/types.py` dataclasses, simplified where the Python
//! shape was carrying around equality semantics it doesn't need: we key
//! lookups by drv path rather than by an `__hash__` of dataclass internals.

use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnresolvedOutput {
    pub output_name: String,
    pub drv_path: String,
    pub input_hash: Option<String>,
    pub unresolved_path: String,
}

impl UnresolvedOutput {
    pub fn udrv_output_id(&self) -> String {
        format!("{}${}", self.drv_path, self.output_name)
    }
}

#[derive(Debug, Clone)]
pub struct UnresolvedReferencedInputs {
    pub derivation: Arc<UnresolvedDerivation>,
    /// Subset of `derivation.outputs` actually referenced by the depender,
    /// keyed by output name. `BTreeMap` for stable ordering.
    pub inputs: BTreeMap<String, UnresolvedOutput>,
}

#[derive(Debug, Clone)]
pub struct UnresolvedDerivation {
    pub drv_path: String,
    pub name: String,
    pub input_hash: String,
    /// `BTreeMap` for stable iteration over outputs.
    pub outputs: BTreeMap<String, UnresolvedOutput>,
    /// One entry per input derivation, holding the subset of its outputs we depend on.
    pub inputs: Vec<UnresolvedReferencedInputs>,
    pub is_fixed_output: bool,
    pub is_content_addressed: bool,
    /// FOD: `outputs["out"]["path"]` from the derivation JSON. `None` for non-FOD.
    pub fod_out_path: Option<String>,
}

/// A trustlessly resolved derivation: the unresolved derivation, the computed
/// resolved drv path (when applicable), the resolved input hash, and the
/// content-hash map for the outputs we observed.
#[derive(Debug, Clone)]
pub struct TrustlesslyResolvedDerivation {
    pub resolves: Arc<UnresolvedDerivation>,
    pub drv_path: Option<String>,
    pub input_hash: String,
    /// Maps each `UnresolvedOutput` (i.e. a `(drv_path, output_name)` of the
    /// unresolved derivation) to the content hash claimed for it.
    pub outputs: BTreeMap<UnresolvedOutput, String>,
}
