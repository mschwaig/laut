//! How the orchestrator obtains derivation data and signatures.
//!
//! Real runs shell out via `laut_sign::nix_cmd` for nix data and dispatch
//! by URL scheme for signatures: `http(s)://` goes over HTTP via
//! `signature_verify::fetch_signatures_from_cache`, `file://` reads from
//! `<path>/traces/<input_hash>` on disk. Tests inject an in-memory backend
//! backed by pre-loaded fixtures so the orchestrator never touches the
//! system `nix` binary or the network.

use std::collections::HashMap;

use laut_sign::cache::{self, CacheTransport};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    NixCmd(#[from] laut_sign::nix_cmd::Error),
    #[error("no aterm fixture for {0:?}")]
    MissingAtermFixture(String),
    #[error("{0}")]
    SignatureFetch(#[from] crate::signature_verify::Error),
    #[error("{0}")]
    Cache(#[from] laut_sign::cache::Error),
}

pub trait Backend {
    /// Return the raw JSON from `nix derivation show --recursive <drv_path>`.
    fn derivation_show_recursive(&self, drv_path: &str) -> Result<String, Error>;

    /// Return the ATerm representation of one derivation (`nix store cat <drv>`).
    fn derivation_aterm(&self, drv_path: &str) -> Result<String, Error>;

    /// Fetch the raw `traces/<input_hash>` body from `cache_url`. `Ok(None)`
    /// means "not in this cache". Real impls do HTTP; test impls read files.
    fn fetch_signatures(
        &self,
        cache_url: &str,
        input_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error>;
}

pub struct RealBackend;

impl Backend for RealBackend {
    fn derivation_show_recursive(&self, drv_path: &str) -> Result<String, Error> {
        Ok(laut_sign::nix_cmd::derivation_show_recursive(drv_path)?)
    }

    fn derivation_aterm(&self, drv_path: &str) -> Result<String, Error> {
        Ok(laut_sign::nix_cmd::derivation_aterm(drv_path)?)
    }

    fn fetch_signatures(
        &self,
        cache_url: &str,
        input_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        match cache::parse_cache_url(cache_url)? {
            CacheTransport::Http(url) => {
                let base_url = match laut_sign::http_cache::parse_http_cache_url(&url) {
                    Ok(b) => b,
                    // Already passed scheme check; only a malformed http URL
                    // gets here. Treat as "not in this cache" rather than
                    // failing the whole verify.
                    Err(_) => return Ok(None),
                };
                Ok(crate::signature_verify::fetch_signatures_from_cache(
                    &base_url, input_hash,
                )?)
            }
            CacheTransport::File(dir) => Ok(cache::read_file_traces(&dir, input_hash)?),
        }
    }
}

/// In-memory backend used by integration tests. Pre-populated from fixture files.
pub struct InMemoryBackend {
    pub recursive_json: String,
    pub aterms: HashMap<String, String>,
    /// `input_hash -> raw signatures-file bytes` (typically `{"signatures": [...]}`)`.
    pub signatures: HashMap<String, Vec<u8>>,
}

impl Backend for InMemoryBackend {
    fn derivation_show_recursive(&self, _drv_path: &str) -> Result<String, Error> {
        Ok(self.recursive_json.clone())
    }

    fn derivation_aterm(&self, drv_path: &str) -> Result<String, Error> {
        self.aterms
            .get(drv_path)
            .cloned()
            .ok_or_else(|| Error::MissingAtermFixture(drv_path.to_owned()))
    }

    fn fetch_signatures(
        &self,
        _cache_url: &str,
        input_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.signatures.get(input_hash).cloned())
    }
}
