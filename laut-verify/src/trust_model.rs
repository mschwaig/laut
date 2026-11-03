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
//! name:thumbprint16` that matches what signers put in the JWS header.
//! `key_file` names a file holding such a string, read at resolution time
//! (the NixOS module uses it for the host's own, runtime-generated key).

use std::path::PathBuf;

use base64::Engine;
use serde::Deserialize;

use crate::string_interner::{KeyId, StringInterner};
use laut_sign::thumbprint;
use crate::verifier::TrustModel;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid key spec {spec:?}: {detail}")]
    InvalidKeySpec { spec: String, detail: String },
    #[error("thumbprint: {0}")]
    Thumbprint(#[from] thumbprint::Error),
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

/// A key spec parsed into its `(name, raw_public_key)` form.
#[derive(Debug)]
struct ParsedKey {
    name: String,
    key_bytes: [u8; 32],
}

fn parse_key_spec(spec: &str) -> Result<ParsedKey, Error> {
    let (name, b64) = spec.split_once(':').ok_or_else(|| Error::InvalidKeySpec {
        spec: spec.to_owned(),
        detail: "expected 'name:base64-public-key'".into(),
    })?;
    if name.is_empty() {
        return Err(Error::InvalidKeySpec {
            spec: spec.to_owned(),
            detail: "key name is empty".into(),
        });
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| Error::InvalidKeySpec {
            spec: spec.to_owned(),
            detail: format!("base64 decode: {e}"),
        })?;
    if raw.len() != 32 {
        return Err(Error::InvalidKeySpec {
            spec: spec.to_owned(),
            detail: format!("expected 32-byte public key, got {}", raw.len()),
        });
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&raw);
    Ok(ParsedKey { name: name.to_owned(), key_bytes })
}

/// Resolve a [`TrustModelSpec`] into a validated [`TrustModel`], interning
/// each leaf's kid. Also returns `(kid, raw_public_key)` per leaf for
/// signature verification; `kid = name:thumbprint16` matches what signers put
/// in the JWS header.
pub fn resolve_spec(
    spec: &TrustModelSpec,
    interner: &mut StringInterner,
) -> Result<(TrustModel, Vec<(String, Vec<u8>)>), Error> {
    let mut keys = Vec::new();
    let model = resolve(spec, interner, &mut keys)?;
    model.validate().map_err(Error::Validation)?;
    Ok((model, keys))
}

fn resolve(
    spec: &TrustModelSpec,
    interner: &mut StringInterner,
    keys: &mut Vec<(String, Vec<u8>)>,
) -> Result<TrustModel, Error> {
    Ok(match spec {
        TrustModelSpec::Key { key } => TrustModel::Key(resolve_key(key, interner, keys)?),
        TrustModelSpec::KeyLegacy { key_legacy } => {
            TrustModel::KeyLegacy(resolve_key(key_legacy, interner, keys)?)
        }
        TrustModelSpec::KeyFile { key_file } => {
            let key = std::fs::read_to_string(key_file).map_err(|source| Error::KeyFile {
                path: key_file.clone(),
                source,
            })?;
            TrustModel::Key(resolve_key(key.trim(), interner, keys)?)
        }
        TrustModelSpec::Threshold { threshold, of } => TrustModel::Threshold(
            *threshold,
            of.iter()
                .map(|child| resolve(child, interner, keys))
                .collect::<Result<_, _>>()?,
        ),
    })
}

fn resolve_key(
    spec: &str,
    interner: &mut StringInterner,
    keys: &mut Vec<(String, Vec<u8>)>,
) -> Result<KeyId, Error> {
    let parsed = parse_key_spec(spec)?;
    let tp = thumbprint::ed25519_thumbprint(&parsed.key_bytes)?;
    let kid = format!("{}:{}", parsed.name, &tp[..16]);
    let id = interner.key(&kid);
    keys.push((kid, parsed.key_bytes.to_vec()));
    Ok(id)
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

    /// The same key referenced in two positions resolves to the same KeyId,
    /// and validation then rejects the model: a key may appear in at most one
    /// leaf (otherwise one signature could light several leaves at once).
    #[test]
    fn same_key_in_two_positions_rejected() {
        let ks = key_spec("a", &[1u8; 32]);
        let spec = TrustModelSpec::Threshold {
            threshold: 2,
            of: vec![
                TrustModelSpec::Key { key: ks.clone() },
                TrustModelSpec::Threshold {
                    threshold: 1,
                    of: vec![
                        TrustModelSpec::Key { key: ks.clone() },
                        TrustModelSpec::Key { key: key_spec("b", &[2u8; 32]) },
                    ],
                },
            ],
        };
        let err = resolve_spec(&spec, &mut StringInterner::new()).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn rejects_bad_key_format() {
        let err = parse_key_spec("no-colon").unwrap_err();
        assert!(matches!(err, Error::InvalidKeySpec { .. }));

        let err = parse_key_spec("a:short").unwrap_err();
        assert!(matches!(err, Error::InvalidKeySpec { .. }));
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
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, format!("{spec}\n").as_bytes()).unwrap();
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
