//! Declarative trust-model configuration.
//!
//! The trust model is the `trust_model` field of the verify config file (see
//! [`crate::config`]). It deserializes into [`TrustModelSpec`], which is then
//! resolved into a [`TrustModel`] the verifier understands.
//!
//! ## Format
//!
//! ```json
//! { "threshold": 2, "of": [
//!     { "key": "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI=" },
//!     { "key": "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M=" }
//! ] }
//! ```
//!
//! `key` and `key_legacy` carry `name:base64-public-key` strings (the same
//! format Nix uses for `trusted-public-keys`). The resolver decodes the
//! public key, computes the JWK thumbprint, and builds the `kid =
//! name:thumbprint16` that signers put in the JWS header.
//! `key_file` names a file holding such a string, read at resolution time
//! (the NixOS module uses it for the host's own, runtime-generated key).
//! [`check_spec`] validates a spec without reading key files.

use std::path::PathBuf;

use nix_compat::narinfo::{VerifyingKey, VerifyingKeyError};
use serde::Deserialize;

use crate::string_interner::{KeyId, StringInterner};
use crate::verifier::TrustModel;
use laut_sign::thumbprint;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid key {spec:?} (expected 'name:base64-public-key'): {source}")]
    InvalidKey {
        spec: String,
        #[source]
        source: VerifyingKeyError,
    },
    #[error("the same public key appears more than once in the trust model (as {first:?} and {second:?})")]
    DuplicateKey { first: String, second: String },
    #[error("trust model validation: {0}")]
    Validation(String),
    #[error("reading key file {path:?}: {source}")]
    KeyFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A declarative trust-model spec, isomorphic to [`TrustModel`] but with
/// keys expressed as `name:base64-public-key` strings instead of interned
/// [`KeyId`]s. Unknown fields are rejected so e.g. `{key, of}` doesn't
/// silently parse as a single key.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum TrustModelSpec {
    /// A single trusted key. `key` is `name:base64-public-key`.
    Key {
        key: String,
    },
    /// A single legacy trusted key. Only allowed as a direct child of a
    /// top-level `Threshold { threshold: 1, ... }`.
    KeyLegacy {
        key_legacy: String,
    },
    /// A single trusted key read from a file containing
    /// `name:base64-public-key`.
    KeyFile {
        key_file: PathBuf,
    },
    /// A threshold of sub-models. `threshold` of the `of` children must be
    /// satisfied.
    Threshold {
        threshold: usize,
        of: Vec<TrustModelSpec>,
    },
}

/// A key signatures are accepted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    /// `name:thumbprint16`; a signature's header `kid` must equal it exactly.
    pub kid: String,
    pub key: ed25519_dalek::VerifyingKey,
}

/// Resolve a [`TrustModelSpec`] into a validated [`TrustModel`], interning
/// each leaf's kid. Also returns the [`TrustedKey`] of every leaf for
/// signature verification.
pub fn resolve_spec(
    spec: &TrustModelSpec,
    interner: &mut StringInterner,
) -> Result<(TrustModel, Vec<TrustedKey>), Error> {
    resolve_validated(spec, interner, true)
}

/// Validate `spec` like [`resolve_spec`] but without reading `key_file`s,
/// which may not exist yet (e.g. in a Nix build sandbox). Each `key_file`
/// leaf stands in as a placeholder key identified by its path.
pub fn check_spec(spec: &TrustModelSpec) -> Result<(), Error> {
    resolve_validated(spec, &mut StringInterner::new(), false).map(|_| ())
}

fn resolve_validated(
    spec: &TrustModelSpec,
    interner: &mut StringInterner,
    read_key_files: bool,
) -> Result<(TrustModel, Vec<TrustedKey>), Error> {
    let mut resolver = Resolver { interner, keys: Vec::new(), read_key_files };
    let model = resolver.resolve(spec)?;
    model.validate().map_err(Error::Validation)?;
    Ok((model, resolver.keys))
}

struct Resolver<'a> {
    interner: &'a mut StringInterner,
    keys: Vec<TrustedKey>,
    read_key_files: bool,
}

impl Resolver<'_> {
    fn resolve(&mut self, spec: &TrustModelSpec) -> Result<TrustModel, Error> {
        Ok(match spec {
            TrustModelSpec::Key { key } => TrustModel::Key(self.resolve_key(key)?),
            TrustModelSpec::KeyLegacy { key_legacy } => {
                TrustModel::KeyLegacy(self.resolve_key(key_legacy)?)
            }
            TrustModelSpec::KeyFile { key_file } if self.read_key_files => {
                let key = std::fs::read_to_string(key_file).map_err(|source| Error::KeyFile {
                    path: key_file.clone(),
                    source,
                })?;
                TrustModel::Key(self.resolve_key(key.trim())?)
            }
            TrustModelSpec::KeyFile { key_file } => {
                TrustModel::Key(self.interner.key(&format!("key_file:{}", key_file.display())))
            }
            TrustModelSpec::Threshold { threshold, of } => TrustModel::Threshold(
                *threshold,
                of.iter()
                    .map(|child| self.resolve(child))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }

    /// Parse `name:base64-public-key`, reject key material already used by
    /// another leaf (under any name), and intern its kid. `validate()` only
    /// sees kids, so it can't catch the same key under two names.
    fn resolve_key(&mut self, spec: &str) -> Result<KeyId, Error> {
        let parsed = VerifyingKey::parse(spec).map_err(|source| Error::InvalidKey {
            spec: spec.to_owned(),
            source,
        })?;
        let key = *parsed.verifying_key();
        let kid = thumbprint::kid(parsed.name(), key.as_bytes());
        if let Some(prev) = self.keys.iter().find(|k| k.key == key) {
            return Err(Error::DuplicateKey { first: prev.kid.clone(), second: kid });
        }
        let id = self.interner.key(&kid);
        self.keys.push(TrustedKey { kid, key });
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;

    fn key_spec(name: &str, seed: &[u8; 32]) -> String {
        let pk = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        format!("{}:{}", name, BASE64.encode(&pk))
    }

    #[test]
    fn single_key_resolves() {
        let spec = TrustModelSpec::Key {
            key: key_spec("builderA", &[1u8; 32]),
        };
        let (tm, _) = resolve_spec(&spec, &mut StringInterner::new()).unwrap();
        assert!(matches!(tm, TrustModel::Key(_)));
    }

    #[test]
    fn threshold_of_two_resolves() {
        let spec = TrustModelSpec::Threshold {
            threshold: 2,
            of: vec![
                TrustModelSpec::Key { key: key_spec("a", &[1u8; 32]) },
                TrustModelSpec::Key { key: key_spec("b", &[2u8; 32]) },
            ],
        };
        let (tm, _) = resolve_spec(&spec, &mut StringInterner::new()).unwrap();
        match tm {
            TrustModel::Threshold(t, children) => {
                assert_eq!(t, 2);
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected Threshold"),
        }
    }

    #[test]
    fn legacy_at_top_level_threshold_one_ok() {
        let spec = TrustModelSpec::Threshold {
            threshold: 1,
            of: vec![
                TrustModelSpec::KeyLegacy { key_legacy: key_spec("cache", &[3u8; 32]) },
                TrustModelSpec::Key { key: key_spec("self", &[4u8; 32]) },
            ],
        };
        let (tm, _) = resolve_spec(&spec, &mut StringInterner::new()).unwrap();
        assert!(matches!(tm, TrustModel::Threshold(1, _)));
    }

    #[test]
    fn legacy_inside_nested_threshold_rejected() {
        let spec = TrustModelSpec::Threshold {
            threshold: 1,
            of: vec![TrustModelSpec::Threshold {
                threshold: 1,
                of: vec![TrustModelSpec::KeyLegacy { key_legacy: key_spec("cache", &[3u8; 32]) }],
            }],
        };
        let err = resolve_spec(&spec, &mut StringInterner::new()).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    /// A key may appear in at most one leaf (otherwise one signature could
    /// light several leaves at once), whatever name it is given and whether
    /// it comes inline, as legacy, or from a file.
    #[test]
    fn same_key_in_two_leaves_rejected() {
        let nested = TrustModelSpec::Threshold {
            threshold: 2,
            of: vec![
                TrustModelSpec::Key { key: key_spec("a", &[1u8; 32]) },
                TrustModelSpec::Threshold {
                    threshold: 1,
                    of: vec![
                        TrustModelSpec::Key { key: key_spec("a", &[1u8; 32]) },
                        TrustModelSpec::Key { key: key_spec("b", &[2u8; 32]) },
                    ],
                },
            ],
        };
        let renamed_legacy = TrustModelSpec::Threshold {
            threshold: 1,
            of: vec![
                TrustModelSpec::KeyLegacy { key_legacy: key_spec("cache", &[1u8; 32]) },
                TrustModelSpec::Key { key: key_spec("self", &[1u8; 32]) },
            ],
        };
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), key_spec("b", &[1u8; 32])).unwrap();
        let renamed_file = TrustModelSpec::Threshold {
            threshold: 2,
            of: vec![
                TrustModelSpec::Key { key: key_spec("a", &[1u8; 32]) },
                TrustModelSpec::KeyFile { key_file: f.path().to_owned() },
            ],
        };
        for spec in [nested, renamed_legacy, renamed_file] {
            let err = resolve_spec(&spec, &mut StringInterner::new()).unwrap_err();
            assert!(matches!(err, Error::DuplicateKey { .. }), "{err}");
        }
    }

    /// Signer sets are u64 bitmasks in the verifier.
    #[test]
    fn more_than_64_keys_rejected() {
        let spec = TrustModelSpec::Threshold {
            threshold: 1,
            of: (0..65u8)
                .map(|i| TrustModelSpec::Key { key: key_spec(&format!("k{i}"), &[i; 32]) })
                .collect(),
        };
        let err = resolve_spec(&spec, &mut StringInterner::new()).unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "{err}");
    }

    #[test]
    fn rejects_bad_key_format() {
        for bad in ["no-colon", "a:short", "bad name:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="] {
            let spec = TrustModelSpec::Key { key: bad.to_owned() };
            let err = resolve_spec(&spec, &mut StringInterner::new()).unwrap_err();
            assert!(matches!(err, Error::InvalidKey { .. }), "{bad}: {err}");
        }
    }

    /// `check_spec` runs where key files don't exist yet (Nix build sandbox).
    #[test]
    fn check_spec_skips_key_files() {
        let spec = TrustModelSpec::Threshold {
            threshold: 2,
            of: vec![
                TrustModelSpec::Key { key: key_spec("a", &[1u8; 32]) },
                TrustModelSpec::KeyFile { key_file: "/nonexistent/local.key.public".into() },
            ],
        };
        check_spec(&spec).unwrap();
        let err = resolve_spec(&spec, &mut StringInterner::new()).unwrap_err();
        assert!(matches!(err, Error::KeyFile { .. }));
    }

    #[test]
    fn serde_key_from_json() {
        let json = r#"{"key":"builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="}"#;
        let spec: TrustModelSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(spec, TrustModelSpec::Key { .. }));
    }

    #[test]
    fn serde_threshold_from_json() {
        let json = r#"{"threshold":2,"of":[{"key":"a:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="},{"key":"b:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="}]}"#;
        let spec: TrustModelSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(spec, TrustModelSpec::Threshold { threshold: 2, .. }));
    }

    #[test]
    fn serde_legacy_from_json() {
        let json = r#"{"key_legacy":"cache:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="}"#;
        let spec: TrustModelSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(spec, TrustModelSpec::KeyLegacy { .. }));
    }

    #[test]
    fn key_file_resolves_like_key() {
        let spec = key_spec("local", &[5u8; 32]);
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), format!("{spec}\n")).unwrap();
        let from_file = TrustModelSpec::KeyFile { key_file: f.path().to_owned() };
        let (_, file_keys) = resolve_spec(&from_file, &mut StringInterner::new()).unwrap();
        let (_, inline_keys) =
            resolve_spec(&TrustModelSpec::Key { key: spec }, &mut StringInterner::new()).unwrap();
        assert_eq!(file_keys, inline_keys);
    }

    #[test]
    fn serde_rejects_unknown_fields() {
        let json = r#"{"key":"a:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI=","of":[]}"#;
        assert!(serde_json::from_str::<TrustModelSpec>(json).is_err());
    }
}
