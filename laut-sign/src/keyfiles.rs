//! Parse Nix-format `name:base64key` key files (signing side).
//!
//! Delegates to snix's `nix_compat::narinfo::signing_keys::parse_keypair`,
//! which validates the Nix name charset, the exact base64 length, and the
//! ed25519 point validity of the embedded public half. We hand back the
//! parsed `ed25519_dalek::SigningKey` directly — requires adding an accessor
//! in snix.

use std::path::Path;

use ed25519_dalek::SigningKey;
use nix_compat::narinfo::{SigningKeyError, parse_keypair};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read key file {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Snix(#[from] SigningKeyError),
}

/// Parse a `name:base64` signing-key string, returning `(name, signing_key)`.
pub fn parse_private_key_content(content: &str) -> Result<(String, SigningKey), Error> {
    let (snix_key, _verifying) = parse_keypair(content.trim())?;
    Ok((snix_key.name().to_owned(), snix_key.signing_key().clone()))
}

/// Read and parse a Nix private-key file from disk.
pub fn parse_private_key_file(path: &Path) -> Result<(String, SigningKey), Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_private_key_content(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64;
    use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};

    /// Build a Nix-formatted `name:base64(seed||pk)` string from a real key,
    /// so the embedded public half is on-curve and snix accepts it.
    fn nix_format(name: &str, seed: &[u8; SECRET_KEY_LENGTH]) -> String {
        let signing = SigningKey::from_bytes(seed);
        let public = signing.verifying_key().to_bytes();
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(seed);
        payload.extend_from_slice(&public);
        format!("{}:{}", name, BASE64.encode(&payload))
    }

    #[test]
    fn parses_real_keypair() {
        let seed = [7u8; SECRET_KEY_LENGTH];
        let (name, signing) = parse_private_key_content(&nix_format("builderA", &seed)).unwrap();
        assert_eq!(name, "builderA");
        assert_eq!(signing.to_bytes(), seed);
    }

    #[test]
    fn trims_whitespace() {
        let seed = [3u8; SECRET_KEY_LENGTH];
        let content = format!("\n  {}\n", nix_format("builderB", &seed));
        let (name, signing) = parse_private_key_content(&content).unwrap();
        assert_eq!(name, "builderB");
        assert_eq!(signing.to_bytes(), seed);
    }

    #[test]
    fn rejects_missing_colon() {
        let err = parse_private_key_content("no-colon-here").unwrap_err();
        assert!(matches!(
            err,
            Error::Snix(SigningKeyError::MissingSeparator)
        ));
    }

    #[test]
    fn rejects_wrong_length() {
        let short = BASE64.encode(&[1u8; 32]);
        let err = parse_private_key_content(&format!("name:{}", short)).unwrap_err();
        assert!(matches!(
            err,
            Error::Snix(SigningKeyError::InvalidSigningKeyLen(_))
        ));
    }
}
