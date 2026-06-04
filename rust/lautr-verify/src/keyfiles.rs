//! Parse Nix-format `name:base64key` public-key files (verify side).
//
// TODO(snix): replace with `nix_compat::narinfo::VerifyingKey::parse` once
// verification stops crossing PyO3 with raw key bytes. Snix validates the
// name charset, exact base64 length, and ed25519 point validity, but its
// `VerifyingKey` doesn't expose the inner key — fine once we verify via
// `VerifyingKey::verify` instead of handing bytes back to Python.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read key file {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("key file is not `name:base64` formatted")]
    MissingSeparator,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("public key payload is {0} bytes, expected 32")]
    InvalidKeyLength(usize),
}

/// Parse a `name:base64` public-key string, returning `(name, key_bytes)`.
pub fn parse_public_key_content(content: &str) -> Result<(String, [u8; 32]), Error> {
    let (name, key_b64) = content
        .trim()
        .split_once(':')
        .ok_or(Error::MissingSeparator)?;
    let decoded = STANDARD.decode(key_b64.as_bytes())?;
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyLength(decoded.len()))?;
    Ok((name.to_owned(), key))
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

    #[test]
    fn parses_name_and_key() {
        let key = [9u8; 32];
        let content = format!("builderA:{}\n", STANDARD.encode(key));
        let (name, parsed) = parse_public_key_content(&content).unwrap();
        assert_eq!(name, "builderA");
        assert_eq!(parsed, key);
    }

    #[test]
    fn rejects_missing_colon() {
        let err = parse_public_key_content("no-colon-here").unwrap_err();
        assert!(matches!(err, Error::MissingSeparator));
    }

    #[test]
    fn rejects_wrong_length() {
        let payload = STANDARD.encode([4u8; 31]);
        let err = parse_public_key_content(&format!("name:{}", payload)).unwrap_err();
        assert!(matches!(err, Error::InvalidKeyLength(31)));
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = parse_public_key_content("name:!!!not-base64!!!").unwrap_err();
        assert!(matches!(err, Error::Base64(_)));
    }
}
