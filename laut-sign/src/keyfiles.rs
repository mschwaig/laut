//! Parse Nix-format `name:base64key` key files (signing side).
//!
//! Delegates to snix's `nix_compat::narinfo::signing_keys::parse_keypair`,
//! which validates the Nix name charset, the exact base64 length, and the
//! ed25519 point validity of the embedded public half. We hand back the
//! parsed `ed25519_dalek::SigningKey` directly — requires adding an accessor
//! in snix.
//!
//! Also generates the keypair for a host without a provided key, see
//! [`generate_keypair`].

use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use nix_compat::narinfo::{SigningKeyError, VerifyingKey, parse_keypair};
use rand::RngCore;

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

/// Where [`generate_keypair`] puts the public half of the key at `secret`.
pub fn public_key_path(secret: &Path) -> PathBuf {
    let mut p = secret.as_os_str().to_owned();
    p.push(".public");
    p.into()
}

/// Generate a Nix-format keypair named `local`: the secret key at `path`
/// (mode 0600) and its public half at [`public_key_path`] (mode 0644). No-op
/// returning `false` if `path` already exists. The public half is renamed
/// into place first, so an existing secret always has its public half next
/// to it.
pub fn generate_keypair(path: &Path) -> Result<bool, Error> {
    if path.exists() {
        return Ok(false);
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let (secret, public) = nix_keypair_strings("local", &SigningKey::from_bytes(&seed));
    write_atomic(&public_key_path(path), 0o644, &public)?;
    write_atomic(path, 0o600, &secret)?;
    Ok(true)
}

/// Nix's `name:base64(seed||pk)` secret and `name:base64(pk)` public key strings.
fn nix_keypair_strings(name: &str, key: &SigningKey) -> (String, String) {
    let secret = format!("{name}:{}", BASE64.encode(&key.to_keypair_bytes()));
    let public = VerifyingKey::new(name.to_owned(), key.verifying_key()).to_string();
    (secret, public)
}

fn write_atomic(path: &Path, mode: u32, content: &str) -> Result<(), Error> {
    let io_err = |source| Error::Io { path: path.display().to_string(), source };
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(io_err)?;
    // `mode()` only applies on creation and is masked by the umask.
    f.set_permissions(Permissions::from_mode(mode)).map_err(io_err)?;
    f.write_all(content.as_bytes()).map_err(io_err)?;
    f.sync_all().map_err(io_err)?;
    std::fs::rename(&tmp, path).map_err(io_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SECRET_KEY_LENGTH;

    /// Build a Nix-formatted `name:base64(seed||pk)` string from a real key,
    /// so the embedded public half is on-curve and snix accepts it.
    fn nix_format(name: &str, seed: &[u8; SECRET_KEY_LENGTH]) -> String {
        nix_keypair_strings(name, &SigningKey::from_bytes(seed)).0
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

    #[test]
    fn generated_keypair_matches_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("local.key");
        assert!(generate_keypair(&secret).unwrap());

        let (name, signing) = parse_private_key_file(&secret).unwrap();
        assert_eq!(name, "local");
        let public = std::fs::read_to_string(public_key_path(&secret)).unwrap();
        let public = VerifyingKey::parse(&public).unwrap();
        assert_eq!(public.name(), "local");
        assert_eq!(*public.verifying_key(), signing.verifying_key());
        let mode = std::fs::metadata(&secret).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let before = std::fs::read(&secret).unwrap();
        assert!(!generate_keypair(&secret).unwrap());
        assert_eq!(std::fs::read(&secret).unwrap(), before);
    }
}
