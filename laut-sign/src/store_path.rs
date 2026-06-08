//! Helpers for inspecting Nix store paths.

use nix_compat::nixbase32;
use nix_compat::store_path::StorePath;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Nix store path {path:?}: {source:?}")]
    Parse {
        path: String,
        source: nix_compat::store_path::Error,
    },
}

/// Return the 32-character nixbase32-encoded digest portion of a Nix store path.
///
/// Accepts any absolute Nix store path (derivations, outputs, sources). The
/// input is parsed by nix-compat so malformed paths and invalid digest
/// characters are rejected up front.
pub fn extract_store_hash(store_path: &str) -> Result<String, Error> {
    let parsed: StorePath<String> =
        StorePath::from_absolute_path(store_path.as_bytes()).map_err(|source| Error::Parse {
            path: store_path.to_owned(),
            source,
        })?;
    Ok(nixbase32::encode(parsed.digest()))
}

/// Return the name suffix (everything after the `<hash>-`) of a Nix store path.
pub fn extract_store_name(store_path: &str) -> Result<String, Error> {
    let parsed: StorePath<String> =
        StorePath::from_absolute_path(store_path.as_bytes()).map_err(|source| Error::Parse {
            path: store_path.to_owned(),
            source,
        })?;
    Ok(parsed.name().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hash_from_drv_path() {
        let hash = extract_store_hash(
            "/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv",
        )
        .expect("valid drv path");
        assert_eq!(hash, "fxz942i5pzia8cgha06swhq216l01p8d");
    }

    #[test]
    fn extracts_hash_from_output_path() {
        let hash =
            extract_store_hash("/nix/store/g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo").expect("valid");
        assert_eq!(hash, "g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q");
    }

    #[test]
    fn rejects_non_store_path() {
        assert!(extract_store_hash("/tmp/foo").is_err());
    }

    #[test]
    fn rejects_invalid_digest_characters() {
        // 'e' is not in the nixbase32 alphabet.
        assert!(extract_store_hash(
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-foo"
        )
        .is_err());
    }
}
