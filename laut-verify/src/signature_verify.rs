//! Admit authenticated SLSA build claims from configured signer keys.

use laut_sign::attestation::{self, parse_bundle};
use std::io::Read;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("attestation: {0}")]
    Attestation(#[from] attestation::Error),
    #[error("http error: {0}")]
    Http(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn fetch_signatures_from_cache(
    base_url: &str,
    input_hash: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        laut_sign::http_cache::trace_path(attestation::NIX_RESOLVED_INPUT, input_hash)
    );
    match ureq::get(&url).call() {
        Ok(resp) => {
            let mut buf = Vec::new();
            resp.into_reader()
                .take(attestation::MAX_OBJECT_BYTES + 1)
                .read_to_end(&mut buf)?;
            if buf.len() as u64 > attestation::MAX_OBJECT_BYTES {
                return Err(Error::Http("cache object too large".into()));
            }
            Ok(Some(buf))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(Error::Http(e.to_string())),
    }
}

/// The returned identity is supplied by the caller's trust configuration,
/// never by unsigned DSSE hints or by a log's admission policy.
pub fn verify_resolved_trace_signatures(
    input_hash: &str,
    signatures: &[String],
    trusted_keys: &[(String, Vec<u8>)],
    log_requirement: Option<&laut_sign::transparency::LogTrust>,
) -> Result<Vec<(serde_json::Value, String)>, Error> {
    let mut out = Vec::new();
    for serialized in signatures {
        let Ok(bundle) = parse_bundle(serialized.as_bytes()) else {
            continue;
        };
        for (identity, bytes) in trusted_keys {
            let Ok(raw): Result<&[u8; 32], _> = bytes.as_slice().try_into() else {
                continue;
            };
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(raw) else {
                continue;
            };
            let Ok(statement) = bundle.verify(&key) else {
                continue;
            };
            // No critical features are supported yet. Signature authentication
            // alone must not turn an unfamiliar execution contract into a vote.
            if statement["predicate"]["buildDefinition"]["externalParameters"]["criticalFeatures"]
                .as_array()
                .is_some_and(|features| !features.is_empty())
            {
                continue;
            }
            if attestation::nix_input_hash(&statement) != Some(input_hash) {
                continue;
            }
            // The format does not require these schemes. This reasoner does:
            // decline the whole atomic claim rather than dropping an output.
            if statement["subject"]
                .as_array()
                .expect("validated subjects")
                .iter()
                .any(|subject| attestation::nix_output_path(subject).is_none())
            {
                continue;
            }
            if log_requirement.is_some_and(|trust| trust.verify(&bundle, &key).is_err()) {
                continue;
            }
            out.push((statement, identity.clone()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn binds_lookup_and_configured_signer_not_hint() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let hash = "0".repeat(32);
        let mut bundle = attestation::create_trace_bundle(&hash, None,
            &json!({"out": {"path": format!("/nix/store/{hash}-test"), "hash": format!("sha256:{}", "0".repeat(52))}}),
            &json!({"out": "CgA"}), 42, None, None, &key, false).unwrap();
        bundle.verification_material.public_key.hint = "attacker".into();
        bundle.dsse_envelope.signatures[0].keyid = "attacker".into();
        let trusted = vec![("configured".into(), key.verifying_key().to_bytes().to_vec())];
        let serialized = serde_json::to_string(&bundle).unwrap();
        let claims =
            verify_resolved_trace_signatures(&hash, &[serialized.clone()], &trusted, None).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1, "configured");
        assert!(
            verify_resolved_trace_signatures(&"1".repeat(32), &[serialized], &trusted, None)
                .unwrap()
                .is_empty()
        );
        bundle.dsse_envelope.signatures[0].sig = attestation::encode([0; 64]);
        assert!(
            verify_resolved_trace_signatures(
                &hash,
                &[serde_json::to_string(&bundle).unwrap()],
                &trusted,
                None,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn critical_features_gate_admission_not_authentication() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let hash = "0".repeat(32);
        let trusted = vec![("configured".into(), key.verifying_key().to_bytes().to_vec())];
        for from_ia in [false, true] {
            let bundle = attestation::create_trace_bundle(&hash, None,
                &json!({"out": {"path": format!("/nix/store/{hash}-test"), "hash": format!("sha256:{}", "0".repeat(52))}}),
                &json!({"out": "CgA"}), 42, None, None, &key, from_ia).unwrap();
            let mut statement = bundle.verify(&key.verifying_key()).unwrap();
            statement["predicate"]["runDetails"]["builder"]["example_host"] =
                json!({"extra": true});
            for features in [
                json!([]),
                json!([""]),
                json!(["gpu-access"]),
                json!(["a", "b"]),
                json!(null),
            ] {
                statement["predicate"]["buildDefinition"]["externalParameters"]["criticalFeatures"] =
                    features.clone();
                let signed = attestation::Bundle::sign(&statement, &key).unwrap();
                assert_eq!(signed.verify(&key.verifying_key()).unwrap(), statement);
                let serialized = serde_json::to_string(&signed).unwrap();
                let claims =
                    verify_resolved_trace_signatures(&hash, &[serialized], &trusted, None).unwrap();
                let expected = usize::from(features.is_null() || features == json!([]));
                assert_eq!(claims.len(), expected, "{features}");
                if expected == 1 {
                    assert_eq!(claims[0].0, statement);
                }
            }
            statement["predicate"]["buildDefinition"]["externalParameters"]
                .as_object_mut()
                .unwrap()
                .remove("criticalFeatures");
            let signed = attestation::Bundle::sign(&statement, &key).unwrap();
            assert_eq!(
                verify_resolved_trace_signatures(
                    &hash,
                    &[serde_json::to_string(&signed).unwrap()],
                    &trusted,
                    None
                )
                .unwrap()
                .len(),
                1
            );
        }
    }

    #[test]
    fn identity_selection_gates_whole_claims_not_authentication() {
        use attestation::{
            NIX_CA_STORE_PATH, NIX_NAR_SHA256, NIX_RESOLVED_INPUT, SNIX_CASTORE_ENTRY,
        };

        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let hash = "0".repeat(32);
        let path = format!("/nix/store/{hash}-test");
        let trusted = vec![("configured".into(), key.verifying_key().to_bytes().to_vec())];
        let bundle = attestation::create_trace_bundle(
            &hash,
            None,
            &json!({"out": {"path": path, "hash": format!("sha256:{}", "0".repeat(52))}}),
            &json!({"out": "CgA"}),
            42,
            None,
            None,
            &key,
            false,
        )
        .unwrap();
        let original = bundle.verify(&key.verifying_key()).unwrap();
        let input = json!({NIX_RESOLVED_INPUT: hash});
        let output = json!({"name": "out", "digest": {NIX_CA_STORE_PATH: path}});
        let unknown_output = json!({"name": "dev", "digest": {"future-store-path": path}});
        let malformed_output = json!({
            "name": "dev",
            "digest": {NIX_CA_STORE_PATH: "relative/path", "future-store-path": path},
        });
        let cases = [
            (
                "store path alone, no mediaType",
                input.clone(),
                json!([output]),
                true,
            ),
            (
                "alternative identities only",
                json!({"future-input": hash}),
                json!([unknown_output]),
                false,
            ),
            (
                "input values do not match across schemes",
                json!({"future-input": hash}),
                json!([output]),
                false,
            ),
            (
                "output values do not match across schemes",
                input.clone(),
                json!([unknown_output]),
                false,
            ),
            (
                "selected input must match cache key",
                json!({NIX_RESOLVED_INPUT: "1".repeat(32), "future-input": hash}),
                json!([output]),
                false,
            ),
            (
                "selected input must be valid base32",
                json!({NIX_RESOLVED_INPUT: "e".repeat(32), "future-input": hash}),
                json!([output]),
                false,
            ),
            (
                "selected input must have current length",
                json!({NIX_RESOLVED_INPUT: "0".repeat(31), "future-input": hash}),
                json!([output]),
                false,
            ),
            (
                "selected path must be absolute",
                input.clone(),
                json!([malformed_output]),
                false,
            ),
            (
                "selected path must be a store path",
                input.clone(),
                json!([{
                    "name": "out", "digest": {NIX_CA_STORE_PATH: format!("/tmp/{hash}-test"), "future-store-path": path},
                }]),
                false,
            ),
            (
                "unknown output last rejects whole claim",
                input.clone(),
                json!([output, unknown_output]),
                false,
            ),
            (
                "unknown output first rejects whole claim",
                input.clone(),
                json!([unknown_output, output]),
                false,
            ),
            (
                "malformed output last rejects whole claim",
                input.clone(),
                json!([output, malformed_output]),
                false,
            ),
            (
                "malformed output first rejects whole claim",
                input.clone(),
                json!([malformed_output, output]),
                false,
            ),
        ];
        for (label, input, subjects, admitted) in cases {
            let mut statement = original.clone();
            statement["predicate"]["buildDefinition"]["externalParameters"]["resolvedInput"]["digest"] =
                input;
            statement["subject"] = subjects;
            let signed = attestation::Bundle::sign(&statement, &key).unwrap();
            assert_eq!(
                signed.verify(&key.verifying_key()).unwrap(),
                statement,
                "{label}"
            );
            let claims = verify_resolved_trace_signatures(
                &hash,
                &[serde_json::to_string(&signed).unwrap()],
                &trusted,
                None,
            )
            .unwrap();
            let expected = if admitted {
                vec![(statement, "configured".into())]
            } else {
                vec![]
            };
            assert_eq!(claims, expected, "{label}");
        }

        // Sibling identities are signed associations, not independently computed
        // equivalences or extra votes. Put unknown schemes on both sides in sort order.
        for reverse in [false, true] {
            let mut inputs = vec![
                ("aaa-future-input", json!("unrelated-input")),
                (NIX_RESOLVED_INPUT, json!(hash)),
                ("zzz-future-input", json!("another-input")),
            ];
            let mut outputs = vec![
                ("aaa-future-output", json!("unrelated-output")),
                (NIX_CA_STORE_PATH, json!(path)),
                (NIX_NAR_SHA256, json!("not-a-nar-hash")),
                (SNIX_CASTORE_ENTRY, json!("not-a-castore-entry")),
                ("zzz-future-output", json!("another-output")),
            ];
            if reverse {
                inputs.reverse();
                outputs.reverse();
            }
            let mut statement = original.clone();
            statement["predicate"]["buildDefinition"]["externalParameters"]["resolvedInput"]["digest"] =
                serde_json::Value::Object(inputs.into_iter().map(|(k, v)| (k.into(), v)).collect());
            statement["subject"][0]["digest"] = serde_json::Value::Object(
                outputs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            );
            let signed = attestation::Bundle::sign(&statement, &key).unwrap();
            assert_eq!(signed.verify(&key.verifying_key()).unwrap(), statement);
            assert_eq!(attestation::nix_input_hash(&statement), Some(hash.as_str()));
            assert_eq!(
                attestation::nix_output_path(&statement["subject"][0]),
                Some(path.as_str())
            );
            let claims = verify_resolved_trace_signatures(
                &hash,
                &[serde_json::to_string(&signed).unwrap()],
                &trusted,
                None,
            )
            .unwrap();
            assert_eq!(claims, vec![(statement, "configured".into())]);
        }
    }
}
