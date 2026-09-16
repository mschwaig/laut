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
    let url = format!("{}/traces/{}", base_url.trim_end_matches('/'), input_hash);
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
            if attestation::input_hash(&statement) != Some(input_hash) {
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
            verify_resolved_trace_signatures(&hash, &[serialized.clone()], &trusted).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1, "configured");
        assert!(
            verify_resolved_trace_signatures(&"1".repeat(32), &[serialized], &trusted)
                .unwrap()
                .is_empty()
        );
        bundle.dsse_envelope.signatures[0].sig = attestation::encode([0; 64]);
        assert!(
            verify_resolved_trace_signatures(
                &hash,
                &[serde_json::to_string(&bundle).unwrap()],
                &trusted
            )
            .unwrap()
            .is_empty()
        );
    }
}
