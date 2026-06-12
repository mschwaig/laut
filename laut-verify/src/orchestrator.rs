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
use laut_sign::{store_path, thumbprint};

use crate::backend::{self, Backend};
use crate::debug::{DebugProbe, NullProbe};
use crate::signature_verify;
use crate::string_interner::{KeyId, StringInterner, UDrv};
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
    #[error("thumbprint: {0}")]
    Thumbprint(#[from] thumbprint::Error),
    #[error("trust model: {0}")]
    TrustModel(String),
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
    /// `(key_name, raw_32_byte_public_key)` for each trusted key.
    pub trusted_keys: Vec<(String, Vec<u8>)>,
    /// Defaults to a `NullProbe`; the verify CLI swaps in a `DifftProbe` when
    /// `--debug-preimage-corpus` is set.
    pub debug_probe: Box<dyn DebugProbe>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            root_drv_path: String::new(),
            cache_urls: Vec::new(),
            trusted_keys: Vec::new(),
            debug_probe: Box::new(NullProbe),
        }
    }
}

pub struct Orchestrator<B: Backend> {
    backend: B,
    cache_urls: Vec<String>,
    /// `(kid, raw_key)` for verification + reasoner; `kid` is `name:thumbprint16`.
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
        if cfg.trusted_keys.is_empty() {
            return Err(Error::TrustModel(
                "No trusted keys configured. Please specify at least one trusted key using --trusted-key".to_owned(),
            ));
        }

        // Resolve names → `kid` so both verification and the trust model use
        // the same string representation. The kid head is the first 16 chars
        // of the JWK thumbprint, matching what the signer puts in the JWS.
        let mut kid_keys: Vec<(String, Vec<u8>)> = Vec::with_capacity(cfg.trusted_keys.len());
        for (name, key_bytes) in &cfg.trusted_keys {
            let tp = thumbprint::ed25519_thumbprint(key_bytes)?;
            let kid = format!("{}:{}", name, &tp[..16]);
            kid_keys.push((kid, key_bytes.clone()));
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

        let mut interner = StringInterner::new();
        let key_ids: Vec<KeyId> = kid_keys.iter().map(|(k, _)| interner.key(k)).collect();
        let threshold = key_ids.len();
        let trust_model = TrustModel::Threshold(
            threshold,
            key_ids.into_iter().map(TrustModel::Key).collect(),
        );
        trust_model.validate().map_err(Error::TrustModel)?;
        let expected_root = interner.udrv(&cfg.root_drv_path);

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
            walker: if matches!(regime, Regime::Ia) {
                Some(laut_sign::ia_closure::Walker::new())
            } else {
                None
            },
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
            Verifier::new(&self.facts, &self.trust_model).map_err(Error::TrustModel)?;

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
