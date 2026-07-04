//! End-to-end verification orchestrator.
//!
//! One DFS over the derivation graph: each udrv visit builds its
//! `UnresolvedDerivation` (via [`tree`]), feeds the verifier's facts and walks
//! the cartesian product of its deps' resolutions (via [`resolutions`]), and
//! returns the set of plausible resolutions for that udrv. Memo on drv_path
//! ensures each udrv is processed once even when it sits under multiple
//! parents. Resolution-hash → ATerm computation and signature fetching live in
//! [`compute`]; success/failure rendering lives in [`report`].

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use laut_sign::drv_json::{self, DrvJson};
use laut_sign::store_path;

use crate::backend::{self, Backend};
use crate::debug::DebugProbe;
use crate::signature_verify;
use crate::string_interner::{StringInterner, UDrv};
use crate::trust_model::{self, TrustModelSpec};
use crate::types::{TrustlesslyResolvedDerivation, UnresolvedDerivation};
use crate::verifier::{Facts, Subset, TrustModel, Verifier, VerifyResult};

mod compute;
mod report;
mod resolutions;
mod tree;

use report::collect_candidate_output_maps;
pub use resolutions::cartesian_product;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("backend: {0}")]
    Backend(#[from] backend::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("derivation {0:?} not found in recursive listing")]
    DerivationNotFound(String),
    #[error(
        "input referenced output {output_name:?} not declared on input derivation {drv_path:?}"
    )]
    UnknownReferencedOutput { drv_path: String, output_name: String },
    #[error(
        "mixed-regime tree: root is {root_regime:?} but {drv_path:?} is {found_regime:?}"
    )]
    MixedRegime {
        root_regime: Regime,
        found_regime: Regime,
        drv_path: String,
    },
    #[error("FOD {drv_path:?} is missing 'out' output path")]
    FodMissingOut { drv_path: String },
    #[error("ia closure: {0}")]
    IaClosure(#[from] laut_sign::ia_closure::Error),
    #[error("constructive trace: {0}")]
    ConstructiveTrace(String),
    #[error("store path: {0}")]
    StorePath(#[from] store_path::Error),
    #[error("signature verify: {0}")]
    SignatureVerify(#[from] signature_verify::Error),
    #[error("trust model config: {0}")]
    TrustModelConfig(#[from] trust_model::Error),
}

/// Addressing regime of the verification target.
///
/// Inferred from the root drv at orchestrator construction. The whole tree is
/// expected to share the regime; cross-regime mixing is rejected as a
/// `MixedRegime` error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    Ca,
    Ia,
}

/// Configuration knobs from the verify CLI surface.
pub struct Config {
    pub root_drv_path: String,
    pub cache_urls: Vec<String>,
    /// Declarative trust model spec (parsed from a Nix config file). The
    /// spec carries its own key material inline as `name:base64` strings.
    pub trust_model: TrustModelSpec,
    /// Defaults to a `NullProbe`; the verify CLI swaps in a `DifftProbe` when
    /// `--debug-preimage-corpus` is set.
    pub debug_probe: Box<dyn DebugProbe>,
}

pub struct Orchestrator<B: Backend> {
    backend: B,
    cache_urls: Vec<String>,
    /// `(kid, raw_key)` for signature verification; `kid` is `name:thumbprint16`.
    /// Built from the trust model spec's inline keys.
    trusted_keys: Vec<(String, Vec<u8>)>,
    pub(crate) regime: Regime,
    debug_probe: Box<dyn DebugProbe>,

    derivations: HashMap<String, DrvJson>,

    interner: StringInterner,
    facts: Facts,
    trust_model: TrustModel,
    expected_root: UDrv,

    /// `drv_path -> unresolved derivation`. Replaces the Python `@cache`.
    tree_memo: HashMap<String, Arc<UnresolvedDerivation>>,
    /// `drv_path -> set of plausible resolutions`. Replaces the Python `@cache`.
    resolutions_memo: HashMap<String, Vec<TrustlesslyResolvedDerivation>>,
    /// `input_hash -> fetched-and-verified (payload, kid)` pairs. Caches a
    /// network + crypto cost across resolution combinations.
    sig_memo: HashMap<String, Vec<(Value, String)>>,
    /// IA closure walker shared across the whole verify run; pass-1 + pass-2
    /// results memoize by IA store path so a path scanned for one udrv's
    /// resolution does not get scanned again for another's. CA runs leave
    /// this `None`.
    pub(crate) walker: Option<laut_sign::ia_closure::Walker>,
}

impl<B: Backend> Orchestrator<B> {
    pub fn new(backend: B, cfg: Config) -> Result<Self, Error> {
        // Build the trust model from the declarative spec. The spec carries
        // its key material inline as `name:base64` strings; we resolve those
        // into `(kid, raw_bytes)` pairs for both the trust model and signature
        // verification.
        let interner = StringInterner::new();
        let (trust_model, mut interner) = trust_model::resolve_spec(&cfg.trust_model, interner)?;

        let mut kid_keys: Vec<(String, Vec<u8>)> = Vec::new();
        for spec_str in trust_model::collect_key_specs(&cfg.trust_model) {
            let (kid, bytes) = trust_model::key_spec_to_kid_and_bytes(&spec_str)?;
            kid_keys.push((kid, bytes));
        }

        let recursive_json = backend.derivation_show_recursive(&cfg.root_drv_path)?;
        let derivations: HashMap<String, DrvJson> = serde_json::from_str(&recursive_json)?;

        // Auto-detect the addressing regime from the root drv. Mixed-regime
        // trees are rejected (caught later in tree.rs) — by design, IA and
        // CA are kept separated for now (per the design notes).
        let root_drv = derivations
            .get(&cfg.root_drv_path)
            .ok_or_else(|| Error::DerivationNotFound(cfg.root_drv_path.clone()))?;
        let (_is_fod, is_ca) = drv_json::classify(&root_drv.outputs);
        let regime = if is_ca { Regime::Ca } else { Regime::Ia };

        let expected_root = interner.udrv(&cfg.root_drv_path);

        let walker = if matches!(regime, Regime::Ia) {
            let mut w = laut_sign::ia_closure::Walker::new();
            let mut global_hashes = std::collections::BTreeSet::new();
            let mut hash_to_path: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for drv in derivations.values() {
                let (is_fod, _) = drv_json::classify(&drv.outputs);
                for output in drv.outputs.values() {
                    if let Some(ref path) = output.path {
                        let full = if path.starts_with("/nix/store/") {
                            path.clone()
                        } else {
                            format!("/nix/store/{}", path)
                        };
                        if let Ok(hash) = store_path::extract_store_hash(&full) {
                            global_hashes.insert(hash.clone());
                            hash_to_path.entry(hash).or_insert(full.clone());
                        }
                        if is_fod {
                            w.register_fod(full);
                        }
                    }
                }
            }
            w.set_global_candidates(global_hashes, hash_to_path);
            Some(w)
        } else {
            None
        };

        Ok(Self {
            backend,
            cache_urls: cfg.cache_urls,
            trusted_keys: kid_keys,
            regime,
            debug_probe: cfg.debug_probe,
            derivations,
            interner,
            facts: Facts::new(),
            trust_model,
            expected_root,
            tree_memo: HashMap::new(),
            resolutions_memo: HashMap::new(),
            sig_memo: HashMap::new(),
            walker,
        })
    }

    /// Run the full verification: walks the graph, feeds the verifier, then
    /// evaluates every candidate output map. Returns a description of every
    /// candidate that verified (empty vec means failure).
    pub fn verify(&mut self) -> Result<Vec<String>, Error> {
        let root_drv_path = self
            .interner
            .udrv_str(self.expected_root)
            .map(str::to_owned)
            .expect("expected_root interned at construction");
        let root_udrv = self.build_unresolved(&root_drv_path)?;

        // In IA mode, walk the root's runtime closure before the resolution
        // pipeline. The walker independently computes synthetic CA paths from
        // on-disk content for all outputs in the runtime closure. These are
        // compared against the signed paths during resolution as a consistency
        // check.
        if matches!(self.regime, Regime::Ia) && !root_udrv.is_fixed_output {
            let walker = self
                .walker
                .as_mut()
                .expect("IA regime requires a walker");
            for udrv_output in root_udrv.outputs.values() {
                let ia_path = &udrv_output.unresolved_path;
                if std::path::Path::new(ia_path).exists() {
                    walker.synthetic_ca_path(ia_path)?;
                }
            }
        }

        let _ = self.collect_resolutions(&root_udrv)?;

        let candidates = collect_candidate_output_maps(&self.facts, self.expected_root);
        if candidates.is_empty() {
            eprintln!(
                "[laut verify] no signed claims found for root udrv {}",
                root_drv_path
            );
            return Ok(Vec::new());
        }

        let mut verifier =
            Verifier::new(&self.facts, &self.trust_model).expect("trust model validated at construction");

        let mut verified = Vec::new();
        let mut successes: Vec<(Subset, VerifyResult)> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        for subset in candidates {
            let result = verifier.verify(self.expected_root, subset.clone());
            if result.verified {
                verified.push(self.format_subset(&subset));
                successes.push((subset, result));
            } else {
                failures.push(self.format_verification_failure(&subset, &result));
            }
        }

        if !successes.is_empty() {
            eprintln!(
                "[laut verify] verification SUCCEEDED for root {}",
                root_drv_path
            );
            for (subset, result) in &successes {
                self.print_success_summary(subset, result);
            }
        } else {
            eprintln!(
                "[laut verify] verification FAILED — all {} candidate output map(s) at the root rejected:",
                failures.len()
            );
            for f in &failures {
                eprint!("{}", f);
            }
        }

        Ok(verified)
    }
}
