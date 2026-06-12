//! Closure walker for the IA→synthetic-CA recursion.
//!
//! Walks the runtime closure of one or more requested root output paths,
//! computing each closure node's synthetic Nix CA store path (via pass-1) and
//! each root's BASE64URL_NOPAD castore Entry of the rewritten content (via
//! pass-2). Results are memoized by the IA store path; the verifier walks the
//! same shape independently.
//!
//! The closure is discovered through `nix-store -q --references` — Nix's own
//! reference-scan output. Per the design notes, the scanner's match set is
//! expected to equal this list exactly; any divergence is a verification
//! failure at the verifier (step 5).

use std::collections::HashMap;
use std::path::Path;

use laut_compat::content_hash::{
    HashError, Pass2Result, rewrite_to_ca_pass1, rewrite_to_ca_pass2,
};
use nix_compat::nixbase32;
use nix_compat::nixhash::NixHash;
use nix_compat::store_path::StorePath;

use crate::nix_cmd::{self, query_references};
use crate::store_path::{self, extract_store_hash, extract_store_name};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("nix cmd: {0}")]
    NixCmd(#[from] nix_cmd::Error),
    #[error("store path: {0}")]
    StorePath(#[from] store_path::Error),
    #[error("hash error: {0}")]
    Hash(String),
}

impl From<HashError> for Error {
    fn from(e: HashError) -> Self {
        Error::Hash(e.to_string())
    }
}

/// Output of [`Walker::root_result`] for one of the requested root output
/// paths: the synthetic Nix CA store path and pass-2 artifacts (castore
/// Entry that goes into the JWS payload, NAR hash + size of the
/// rewritten content for stamping `payload.out.nix[name].hash`).
pub struct RootResult {
    pub synthetic_ca_path: StorePath<String>,
    pub castore_entry_base64: String,
    pub nar_hash: NixHash,
    pub nar_size: u64,
}

struct MemoEntry {
    synthetic_ca_path: StorePath<String>,
}

/// Recursive walker; one instance covers the closure of all roots passed
/// through it (the memo is shared).
pub struct Walker {
    memo: HashMap<String, MemoEntry>,
}

impl Walker {
    pub fn new() -> Self {
        Walker {
            memo: HashMap::new(),
        }
    }

    /// Synthetic CA hash (32-char nixbase32) of `path`'s rewritten-content
    /// equivalent. Recursively processes the path's runtime references first
    /// and memoizes by IA store path.
    pub fn synthetic_ca_hash(&mut self, path: &str) -> Result<String, Error> {
        if let Some(entry) = self.memo.get(path) {
            return Ok(nixbase32::encode(entry.synthetic_ca_path.digest()));
        }
        let sp = self.compute_pass1(path)?;
        let hash = nixbase32::encode(sp.digest());
        self.memo
            .insert(path.to_owned(), MemoEntry { synthetic_ca_path: sp });
        Ok(hash)
    }

    /// Synthetic CA store path of `path`. Wraps [`synthetic_ca_hash`] so the
    /// caller doesn't have to reconstruct the path from name + hash.
    pub fn synthetic_ca_path(&mut self, path: &str) -> Result<StorePath<String>, Error> {
        self.synthetic_ca_hash(path)?;
        Ok(self.memo[path].synthetic_ca_path.clone())
    }

    fn compute_pass1(&mut self, path: &str) -> Result<StorePath<String>, Error> {
        // TODO (sanity check): once `rewrite_to_ca_pass1`/`pass2` expose the
        // matched-needles set, assert it equals `refs` exactly. A mismatch
        // means our reference scanner disagrees with what Nix's path-info
        // records — fatal at verify time (see step 5 design notes).
        let refs = query_references(path)?;
        let self_ia_hash = extract_store_hash(path)?;

        let mut deps_rewrites: HashMap<String, String> = HashMap::new();
        let mut refs_as_ca: Vec<String> = Vec::new();
        for r in &refs {
            if r == path {
                // Self-ref handled by the self_mask inside pass1.
                continue;
            }
            let ref_ia_hash = extract_store_hash(r)?;
            let ref_ca_hash = self.synthetic_ca_hash(r)?;
            deps_rewrites.insert(ref_ia_hash, ref_ca_hash);
            refs_as_ca.push(self.memo[r].synthetic_ca_path.to_absolute_path());
        }

        let name = extract_store_name(path)?;
        let sp = rewrite_to_ca_pass1(
            Path::new(path),
            &name,
            &deps_rewrites,
            &self_ia_hash,
            &refs_as_ca,
        )?;
        Ok(sp)
    }

    /// Compute pass-2 for a requested root output: the BASE64URL_NOPAD castore
    /// Entry of the rewritten content. Self-reference rewrite is included so
    /// the entry reflects the fully CA-equivalent form.
    pub fn root_result(&mut self, out_path: &str) -> Result<RootResult, Error> {
        // Drive pass-1 for the root so we know its synthetic CA hash. Then
        // rewrite the content using deps + self.
        let synthetic_ca_path = self.synthetic_ca_path(out_path)?;
        let self_ia_hash = extract_store_hash(out_path)?;
        let self_ca_hash = nixbase32::encode(synthetic_ca_path.digest());

        let mut rewrites: HashMap<String, String> = HashMap::new();
        rewrites.insert(self_ia_hash, self_ca_hash);

        let refs = query_references(out_path)?;
        for r in &refs {
            if r == out_path {
                continue;
            }
            let ref_ia_hash = extract_store_hash(r)?;
            let ref_ca_hash = self.synthetic_ca_hash(r)?;
            rewrites.insert(ref_ia_hash, ref_ca_hash);
        }

        let Pass2Result {
            castore_entry_base64,
            nar_hash,
            nar_size,
        } = rewrite_to_ca_pass2(Path::new(out_path), &rewrites)?;
        Ok(RootResult {
            synthetic_ca_path,
            castore_entry_base64,
            nar_hash,
            nar_size,
        })
    }

    /// Read-only memo lookup: synthetic CA path of a path already processed,
    /// or `None` if it hasn't been visited yet. Used by `sign.rs` to look up
    /// input drvs' outputs after the closure walk has driven them in.
    pub fn lookup(&self, path: &str) -> Option<&StorePath<String>> {
        self.memo.get(path).map(|e| &e.synthetic_ca_path)
    }
}

impl Default for Walker {
    fn default() -> Self {
        Self::new()
    }
}
