//! Signature caches, shared by signer and verifier: cache URL parsing, the
//! `traces/<input_hash>` layout and its `{ "signatures": [...] }` document.
//!
//! `http(s)://` caches are uploaded to by [`crate::http_cache`]. `file://`
//! directories (a host's own local signing key) are written here by the
//! post-build hook, which the nix-daemon may run concurrently: writers
//! serialize read-merge-write on `traces/.lock`, and write-then-rename keeps
//! (lock-free) readers from seeing a partial file.

use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported cache URL {0:?} (expected http://, https://, or file://)")]
    UnsupportedUrl(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] crate::http_cache::Error),
}

/// A parsed cache URL. Deserializes from its URL string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub enum CacheTransport {
    /// Canonical base URL, see [`crate::http_cache::parse_http_cache_url`].
    Http(String),
    File(PathBuf),
}

impl TryFrom<String> for CacheTransport {
    type Error = Error;
    fn try_from(url: String) -> Result<Self, Error> {
        parse_cache_url(&url)
    }
}

/// Unknown schemes are an error — silently skipping them hides misconfiguration.
pub fn parse_cache_url(url: &str) -> Result<CacheTransport, Error> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(CacheTransport::Http(crate::http_cache::parse_http_cache_url(url)?))
    } else if let Some(rest) = url.strip_prefix("file://") {
        Ok(CacheTransport::File(PathBuf::from(rest)))
    } else {
        Err(Error::UnsupportedUrl(url.to_owned()))
    }
}

pub fn traces_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join("traces")
}

/// Read `<cache_dir>/traces/<input_hash>`, or `None` if there is none.
pub fn read_file_traces(cache_dir: &Path, input_hash: &str) -> Result<Option<Vec<u8>>, Error> {
    match fs::read(traces_dir(cache_dir).join(input_hash)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Add `signature` to an existing traces document (or start a new one).
/// Returns the new document body, or `None` if the signature is already there.
pub(crate) fn merge_signature(existing: Option<Value>, signature: &str) -> Option<String> {
    let mut signatures = match existing {
        Some(Value::Object(mut doc)) => match doc.remove("signatures") {
            Some(Value::Array(sigs)) => sigs,
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    if signatures.iter().any(|s| s.as_str() == Some(signature)) {
        return None;
    }
    signatures.push(Value::String(signature.to_owned()));
    Some(json!({ "signatures": signatures }).to_string())
}

/// Append `signature` to `<cache_dir>/traces/<input_hash>`.
pub fn write_file_signature(cache_dir: &Path, input_hash: &str, signature: &str) -> Result<(), Error> {
    let traces = traces_dir(cache_dir);
    fs::create_dir_all(&traces)?;
    // Released when dropped.
    let lock = File::create(traces.join(".lock"))?;
    lock.lock()?;

    let existing = read_file_traces(cache_dir, input_hash)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    let Some(body) = merge_signature(existing, signature) else {
        return Ok(());
    };

    let tmp = traces.join(format!(".{input_hash}.tmp"));
    let mut f = File::create(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, traces.join(input_hash))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_appends_and_dedups() {
        let doc = merge_signature(None, "a").unwrap();
        let doc = merge_signature(Some(serde_json::from_str(&doc).unwrap()), "b").unwrap();
        let parsed: Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(parsed, json!({ "signatures": ["a", "b"] }));
        assert!(merge_signature(Some(parsed), "a").is_none());
    }

    #[test]
    fn file_writes_merge_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        write_file_signature(dir.path(), "h", "a").unwrap();
        write_file_signature(dir.path(), "h", "b").unwrap();
        write_file_signature(dir.path(), "h", "a").unwrap();
        let doc: Value =
            serde_json::from_slice(&read_file_traces(dir.path(), "h").unwrap().unwrap()).unwrap();
        assert_eq!(doc, json!({ "signatures": ["a", "b"] }));
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(matches!(parse_cache_url("s3://bucket"), Err(Error::UnsupportedUrl(_))));
    }
}
