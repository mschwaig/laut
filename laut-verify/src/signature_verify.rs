//! Fetch JWS signatures from an S3-backed cache and verify them against trusted keys.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signature;
use std::io::Read;

use crate::trust_model::TrustedKey;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid jwt structure")]
    InvalidJwtStructure,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
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
            resp.into_reader().read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(Error::Http(format!("{}", e))),
    }
}

/// Verify an EdDSA JWS compact serialization against the trusted key whose kid
/// equals the header `kid` exactly (name included), and return the parsed
/// payload + that kid. Returns `None` if no trusted key has that kid or the
/// signature doesn't validate.
fn verify_jws_eddsa(
    jws: &str,
    trusted_keys: &[TrustedKey],
) -> Result<Option<(serde_json::Value, String)>, Error> {
    let mut parts = jws.split('.');
    let header_b64 = parts.next().ok_or(Error::InvalidJwtStructure)?;
    let payload_b64 = parts.next().ok_or(Error::InvalidJwtStructure)?;
    let sig_b64 = parts.next().ok_or(Error::InvalidJwtStructure)?;
    if parts.next().is_some() {
        return Err(Error::InvalidJwtStructure);
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
    let Some(trusted) = header
        .get("kid")
        .and_then(|v| v.as_str())
        .and_then(|kid| trusted_keys.iter().find(|k| k.kid == kid))
    else {
        return Ok(None);
    };

    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSignatureLength(sig_bytes.len()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let signed_message = format!("{}.{}", header_b64, payload_b64);
    if trusted
        .key
        .verify_strict(signed_message.as_bytes(), &signature)
        .is_err()
    {
        return Ok(None);
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;
    Ok(Some((payload, trusted.kid.clone())))
}

/// For each signature: verify the JWS against the trusted key with its kid, and
/// check that the payload's `in.rdrv_aterm_ca` matches `input_hash` and
/// `out.nix` is an object. Returns `(payload, kid)` for every accepted
/// signature.
pub fn verify_resolved_trace_signatures(
    input_hash: &str,
    signatures: &[String],
    trusted_keys: &[TrustedKey],
) -> Vec<(serde_json::Value, String)> {
    let mut out = Vec::new();
    for signature in signatures {
        let (payload, kid) = match verify_jws_eddsa(signature, trusted_keys) {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => continue,
        };
        let rdrv = payload
            .get("in")
            .and_then(|v| v.get("rdrv_aterm_ca"))
            .and_then(|v| v.as_str());
        if rdrv != Some(input_hash) {
            continue;
        }
        if !payload
            .get("out")
            .and_then(|v| v.get("nix"))
            .map(|v| v.is_object())
            .unwrap_or(false)
        {
            continue;
        }
        out.push((payload, kid));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use laut_sign::thumbprint;

    fn make_key() -> SigningKey {
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn trusted(name: &str, sk: &SigningKey) -> Vec<TrustedKey> {
        let key = sk.verifying_key();
        vec![TrustedKey { kid: thumbprint::kid(name, key.as_bytes()), key }]
    }

    fn payload(input_hash: &str) -> serde_json::Value {
        serde_json::json!({
            "in": { "rdrv_aterm_ca": input_hash },
            "out": { "nix": { "out": { "path": "/nix/store/x" } } },
        })
    }

    fn make_jws(signing_key: &SigningKey, header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{}.{}", signing_input, sig_b64)
    }

    #[test]
    fn verify_round_trip() {
        let sk = make_key();
        let header = serde_json::json!({ "alg": "EdDSA", "kid": trusted("test", &sk)[0].kid });
        let jws = make_jws(&sk, &header, &payload("abc123"));

        let results =
            verify_resolved_trace_signatures("abc123", &[jws.clone()], &trusted("test", &sk));
        assert_eq!(results.len(), 1);

        let wrong = verify_resolved_trace_signatures("wronghash", &[jws], &trusted("test", &sk));
        assert_eq!(wrong.len(), 0);
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let sk = make_key();
        let header = serde_json::json!({ "alg": "EdDSA", "kid": trusted("test", &sk)[0].kid });
        let mut jws = make_jws(&sk, &header, &payload("abc123"));
        // Flip a character in the signature.
        let last = jws.pop().unwrap();
        jws.push(if last == 'A' { 'B' } else { 'A' });

        let results = verify_resolved_trace_signatures("abc123", &[jws], &trusted("test", &sk));
        assert_eq!(results.len(), 0);
    }

    /// Right key, wrong name in the kid: the signature names a different
    /// trust-model leaf than the one configured for this key.
    #[test]
    fn verify_rejects_kid_name_mismatch() {
        let sk = make_key();
        let header = serde_json::json!({ "alg": "EdDSA", "kid": trusted("other", &sk)[0].kid });
        let jws = make_jws(&sk, &header, &payload("abc123"));

        let results = verify_resolved_trace_signatures("abc123", &[jws], &trusted("test", &sk));
        assert_eq!(results.len(), 0);
    }
}
