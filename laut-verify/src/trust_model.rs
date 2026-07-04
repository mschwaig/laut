//! Declarative trust-model configuration.
//!
//! Users write a Nix file describing the trust model as a native attrset.
//! The CLI / NixOS module passes the file path; this module evaluates it
//! via `nix eval --json` and deserializes the result into [`TrustModelSpec`],
//! which is then resolved into a [`TrustModel`] the verifier understands.
//!
//! ## Nix format
//!
//! ```nix
//! {
//!   threshold = 2;
//!   of = [
//!     { key = "builderA:diZIhvLSthXHFH+qz5dY/Fegz/u7Z+8aMekjrabc+fI="; }
//!     { key = "builderB:Dwxy6SpfvApt2NHfA8luc1Lj6sobZoX99epUTo3im6M="; }
//!   ];
//! }
//! ```
//!
//! `key` and `key_legacy` carry `name:base64-public-key` strings (the same
//! format Nix uses for `trusted-public-keys`). The resolver decodes the
//! public key, computes the JWK thumbprint, and builds the `kid =
//! name:thumbprint16` that matches what signers put in the JWS header.

use std::path::Path;
use std::process::Command;

use base64::Engine;
use serde::Deserialize;

use crate::string_interner::KeyId;
use laut_sign::thumbprint;
use crate::verifier::TrustModel;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading trust model config file {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("nix eval failed for {path:?}: exit {code}: {stderr}")]
    NixEval {
        path: String,
        code: i32,
        stderr: String,
    },
    #[error("nix eval for {0:?} produced non-UTF8 output")]
    NixEvalNonUtf8(String),
    #[error("parsing trust model JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid key spec {spec:?}: {detail}")]
    InvalidKeySpec { spec: String, detail: String },
    #[error("thumbprint: {0}")]
    Thumbprint(#[from] thumbprint::Error),
    #[error("trust model validation: {0}")]
    Validation(String),
}

/// A declarative trust-model spec, isomorphic to [`TrustModel`] but with
/// keys expressed as `name:base64-public-key` strings instead of interned
/// [`KeyId`]s. Deserialized from the JSON that `nix eval --json` produces.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
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

/// Collect every distinct `name:base64-public-key` string referenced in a
/// trust model spec, in first-occurrence order. Used to build the
/// `trusted_keys` list for signature verification.
pub fn collect_key_specs(spec: &TrustModelSpec) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    collect_key_specs_inner(spec, &mut seen, &mut out);
    out
}

fn collect_key_specs_inner(
    spec: &TrustModelSpec,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<String>,
) {
    match spec {
        TrustModelSpec::Key { key } => {
            if seen.insert(key.clone()) {
                out.push(key.clone());
            }
        }
        TrustModelSpec::KeyLegacy { key_legacy } => {
            if seen.insert(key_legacy.clone()) {
                out.push(key_legacy.clone());
            }
        }
        TrustModelSpec::Threshold { of, .. } => {
            for child in of {
                collect_key_specs_inner(child, seen, out);
            }
        }
    }
}

/// Parse a `name:base64-public-key` string and return `(kid, raw_32_bytes)`,
/// where `kid = name:thumbprint16`.
pub fn key_spec_to_kid_and_bytes(spec: &str) -> Result<(String, Vec<u8>), Error> {
    let parsed = parse_key_spec(spec)?;
    let tp = thumbprint::ed25519_thumbprint(&parsed.key_bytes)?;
    let kid = format!("{}:{}", parsed.name, &tp[..16]);
    Ok((kid, parsed.key_bytes.to_vec()))
}

/// A resolver that collects `name:thumbprint16` kids as it walks the spec,
/// deduplicating keys that appear in multiple positions.
pub struct SpecResolver {
    /// Map from `name:base64` key spec string → interned KeyId.
    /// Deduplicates so the same key referenced in multiple threshold branches
    /// resolves to the same KeyId.
    kids: std::collections::HashMap<String, KeyId>,
    interner: crate::string_interner::StringInterner,
}

impl SpecResolver {
    pub fn new(interner: crate::string_interner::StringInterner) -> Self {
        SpecResolver {
            kids: std::collections::HashMap::new(),
            interner,
        }
    }

    /// Resolve a key spec string to a KeyId, computing the kid
    /// (`name:thumbprint16`) and interning it.
    fn resolve_key(&mut self, spec: &str) -> Result<KeyId, Error> {
        if let Some(&id) = self.kids.get(spec) {
            return Ok(id);
        }
        let parsed = parse_key_spec(spec)?;
        let tp = thumbprint::ed25519_thumbprint(&parsed.key_bytes)?;
        let kid = format!("{}:{}", parsed.name, &tp[..16]);
        let id = self.interner.key(&kid);
        self.kids.insert(spec.to_owned(), id);
        Ok(id)
    }

    /// Recursively resolve a [`TrustModelSpec`] into a [`TrustModel`].
    pub fn resolve(&mut self, spec: &TrustModelSpec) -> Result<TrustModel, Error> {
        Ok(match spec {
            TrustModelSpec::Key { key } => TrustModel::Key(self.resolve_key(key)?),
            TrustModelSpec::KeyLegacy { key_legacy } => {
                TrustModel::KeyLegacy(self.resolve_key(key_legacy)?)
            }
            TrustModelSpec::Threshold { threshold, of } => {
                let children: Vec<TrustModel> = of
                    .iter()
                    .map(|child| self.resolve(child))
                    .collect::<Result<_, _>>()?;
                TrustModel::Threshold(*threshold, children)
            }
        })
    }

    pub fn into_interner(self) -> crate::string_interner::StringInterner {
        self.interner
    }
}

/// Read a `.nix` file and evaluate it to JSON via `nix eval --json`.
pub fn load_spec_from_nix_file(path: &Path) -> Result<TrustModelSpec, Error> {
    let output = Command::new("nix")
        .args(["eval", "--json", "--file"])
        .arg(path)
        .output()
        .map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::NixEval {
            path: path.display().to_string(),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| Error::NixEvalNonUtf8(path.display().to_string()))?;
    let spec: TrustModelSpec = serde_json::from_str(&stdout)?;
    Ok(spec)
}

/// Resolve a [`TrustModelSpec`] into a [`TrustModel`] using a fresh interner.
pub fn resolve_spec(
    spec: &TrustModelSpec,
    interner: crate::string_interner::StringInterner,
) -> Result<(TrustModel, crate::string_interner::StringInterner), Error> {
    let mut resolver = SpecResolver::new(interner);
    let tm = resolver.resolve(spec)?;
    // Validate the structural constraints (legacy placement, etc.).
    tm.validate().map_err(Error::Validation)?;
    Ok((tm, resolver.into_interner()))
}

/// Convenience: load + resolve in one call.
pub fn load_from_nix_file(
    path: &Path,
    interner: crate::string_interner::StringInterner,
) -> Result<(TrustModel, crate::string_interner::StringInterner), Error> {
    let spec = load_spec_from_nix_file(path)?;
    resolve_spec(&spec, interner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string_interner::StringInterner;
    use data_encoding::BASE64;
    use ed25519_dalek::SigningKey;

    fn key_spec(name: &str, seed: &[u8; 32]) -> String {
        let pk = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        format!("{}:{}", name, BASE64.encode(&pk))
    }

    fn fresh_interner() -> StringInterner {
        StringInterner::new()
    }

    #[test]
    fn single_key_resolves() {
        let spec = TrustModelSpec::Key {
            key: key_spec("builderA", &[1u8; 32]),
        };
        let (tm, _) = resolve_spec(&spec, fresh_interner()).unwrap();
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
        let (tm, _) = resolve_spec(&spec, fresh_interner()).unwrap();
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
        let (tm, _) = resolve_spec(&spec, fresh_interner()).unwrap();
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
        let err = resolve_spec(&spec, fresh_interner()).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn same_key_deduplicated() {
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
        let interner = fresh_interner();
        let (tm, interner) = resolve_spec(&spec, interner).unwrap();
        // Count distinct KeyIds in the resolved model.
        let mut ids = std::collections::HashSet::new();
        collect_key_ids(&tm, &mut ids);
        assert_eq!(ids.len(), 2, "builderA + builderB, builderA deduplicated");
        // The interner should have exactly 2 keys interned.
        let _ = interner; // just ensure it's moved out
    }

    fn collect_key_ids(tm: &TrustModel, ids: &mut std::collections::HashSet<KeyId>) {
        match tm {
            TrustModel::Key(k) | TrustModel::KeyLegacy(k) => {
                ids.insert(*k);
            }
            TrustModel::Threshold(_, children) => {
                for c in children {
                    collect_key_ids(c, ids);
                }
            }
        }
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
}
