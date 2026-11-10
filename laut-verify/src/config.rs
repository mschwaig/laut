//! `laut verify` config file: the caches to query and the trust model.
//!
//! The NixOS module writes it to [`DEFAULT_PATH`] from
//! `services.laut.verify`, so a bare `laut verify <target>` works there.
//!
//! ```json
//! {
//!   "caches": ["https://cache.example.org", "file:///var/lib/laut"],
//!   "trust_model": { "threshold": 1, "of": [
//!     { "key": "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI=" },
//!     { "key_file": "/var/lib/laut/local.key.public" }
//!   ] }
//! }
//! ```

use std::path::{Path, PathBuf};

use laut_sign::cache::CacheTransport;
use serde::Deserialize;

use crate::trust_model::TrustModelSpec;

pub const DEFAULT_PATH: &str = "/etc/laut/verify.json";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyConfig {
    #[serde(default)]
    pub caches: Vec<CacheTransport>,
    pub trust_model: TrustModelSpec,
}

pub fn load(path: &Path) -> Result<VerifyConfig, Error> {
    let bytes = std::fs::read(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| Error::Json {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_caches_and_trust_model() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            br#"{"caches":["file:///var/lib/laut"],"trust_model":{"key":"a:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="}}"#,
        )
        .unwrap();
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.caches, vec![CacheTransport::File("/var/lib/laut".into())]);
        assert!(matches!(cfg.trust_model, TrustModelSpec::Key { .. }));
    }

    #[test]
    fn rejects_unknown_cache_scheme() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            br#"{"caches":["s3://bucket"],"trust_model":{"key":"a:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="}}"#,
        )
        .unwrap();
        assert!(matches!(load(f.path()), Err(Error::Json { .. })));
    }
}
