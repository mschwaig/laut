//! Parse Nix-format `name:base64key` key files (signing side).
//!
//! Nix stores ed25519 keys as a single line of `name:base64`. The base64
//! payload of a private key is 64 bytes — a 32-byte seed (the actual ed25519
//! private key) followed by the 32-byte public key — and we keep just the
//! first 32 bytes, matching how `nix-store --generate-binary-cache-key`
//! produces them.
//
// TODO(snix): replace with `nix_compat::narinfo::signing_keys::parse_keypair`
// once signing happens in Rust. Snix validates the Nix name charset, exact
// base64 length, and ed25519 point validity, but its `SigningKey` doesn't
// expose the inner key — fine once we sign via `Signer::sign` instead of
// shipping seed bytes back to Python.

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
    #[error("private key payload is {0} bytes, expected at least 32")]
    PrivateKeyTooShort(usize),
}

/// Parse a `name:base64` private-key string, returning `(name, seed_bytes)`.
///
/// `seed_bytes` is the 32-byte ed25519 seed sliced off the front of the
/// base64-decoded payload.
pub fn parse_private_key_content(content: &str) -> Result<(String, [u8; 32]), Error> {
    let (name, key_b64) = content
        .trim()
        .split_once(':')
        .ok_or(Error::MissingSeparator)?;
    let decoded = STANDARD.decode(key_b64.as_bytes())?;
    if decoded.len() < 32 {
        return Err(Error::PrivateKeyTooShort(decoded.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded[..32]);
    Ok((name.to_owned(), seed))
}

/// Read and parse a Nix private-key file from disk.
pub fn parse_private_key_file(path: &Path) -> Result<(String, [u8; 32]), Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_private_key_content(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn encode(seed: &[u8; 32]) -> String {
        // Mimic `nix-store --generate-binary-cache-key`: 64-byte payload of
        // seed || public-key. For the parser we don't actually need a valid
        // public key — any 32 trailing bytes will do.
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(seed);
        payload.extend_from_slice(&[0u8; 32]);
        STANDARD.encode(&payload)
    }

    #[test]
    fn parses_name_and_seed() {
        let seed = [7u8; 32];
        let content = format!("builderA:{}\n", encode(&seed));
        let (name, parsed) = parse_private_key_content(&content).unwrap();
        assert_eq!(name, "builderA");
        assert_eq!(parsed, seed);
    }

    #[test]
    fn trims_whitespace() {
        let seed = [3u8; 32];
        let content = format!("   builderB:{}\n\n", encode(&seed));
        let (name, parsed) = parse_private_key_content(&content).unwrap();
        assert_eq!(name, "builderB");
        assert_eq!(parsed, seed);
    }

    #[test]
    fn rejects_missing_colon() {
        let err = parse_private_key_content("no-colon-here").unwrap_err();
        assert!(matches!(err, Error::MissingSeparator));
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = parse_private_key_content("name:!!!not-base64!!!").unwrap_err();
        assert!(matches!(err, Error::Base64(_)));
    }

    #[test]
    fn rejects_short_payload() {
        let short = STANDARD.encode([1u8; 16]);
        let err = parse_private_key_content(&format!("name:{}", short)).unwrap_err();
        assert!(matches!(err, Error::PrivateKeyTooShort(16)));
    }
}
