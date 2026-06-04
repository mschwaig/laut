//! NAR hash and castore-entry helpers used by signing.

use std::path::Path;

use laut_compat::content_hash;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Inner(String),
}

pub fn calculate_nar_hash(path: &Path) -> Result<String, Error> {
    let (hash, _size) =
        content_hash::calculate_nar_hash(path, None).map_err(|e| Error::Inner(format!("{}", e)))?;
    Ok(content_hash::format_nar_hash(&hash))
}

pub fn create_castore_entry(path: &Path) -> Result<String, Error> {
    content_hash::create_castore_entry(path).map_err(|e| Error::Inner(format!("{}", e)))
}
