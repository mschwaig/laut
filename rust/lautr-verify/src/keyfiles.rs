//! Parse Nix-format `name:base64key` public-key files (verify side).
//!
//! Delegates to snix's `nix_compat::narinfo::VerifyingKey::parse`, which
//! validates the Nix name charset, the exact base64 length, and the ed25519
//! point validity of the encoded key. Exposing the inner
//! `ed25519_dalek::VerifyingKey` requires adding an accessor in snix.

use std::path::Path;

use nix_compat::narinfo::{VerifyingKey, VerifyingKeyError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read key file {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Snix(#[from] VerifyingKeyError),
}

/// Parse a `name:base64` public-key string, returning `(name, key_bytes)`.
pub fn parse_public_key_content(content: &str) -> Result<(String, [u8; 32]), Error> {
    let parsed = VerifyingKey::parse(content.trim())?;
    Ok((
        parsed.name().to_owned(),
        parsed.verifying_key().to_bytes(),
    ))
}

/// Read and parse a Nix public-key file from disk.
pub fn parse_public_key_file(path: &Path) -> Result<(String, [u8; 32]), Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_public_key_content(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;

    /// Snix validates ed25519 point validity, so tests must use a real public key.
    fn nix_format(name: &str, seed: &[u8; 32]) -> String {
        let pk = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        format!("{}:{}", name, BASE64.encode(&pk))
    }

    #[test]
    fn parses_real_public_key() {
        let seed = [9u8; 32];
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let (name, parsed) = parse_public_key_content(&nix_format("builderA", &seed)).unwrap();
        assert_eq!(name, "builderA");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn rejects_missing_colon() {
        let err = parse_public_key_content("no-colon-here").unwrap_err();
        assert!(matches!(
            err,
            Error::Snix(VerifyingKeyError::MissingSeparator)
        ));
    }

    #[test]
    fn rejects_wrong_length() {
        // 16-byte payload base64-encodes to 24 chars; snix expects the exact
        // length for a 32-byte key (44 chars) and rejects up front.
        let payload = BASE64.encode(&[4u8; 16]);
        let err = parse_public_key_content(&format!("name:{}", payload)).unwrap_err();
        assert!(matches!(
            err,
            Error::Snix(VerifyingKeyError::InvalidVerifyingKeyLen(_))
        ));
    }
}
