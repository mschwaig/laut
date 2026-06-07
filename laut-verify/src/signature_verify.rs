//! Fetch JWS signatures from an S3-backed cache and verify them against trusted keys.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use laut_sign::thumbprint::{self, ed25519_thumbprint};
use std::io::Read;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    #[error("invalid public key bytes")]
    InvalidKey,
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
    #[error("{0}")]
    Thumbprint(#[from] thumbprint::Error),
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

fn verifying_key_from_bytes(public_key: &[u8]) -> Result<VerifyingKey, Error> {
    let arr: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::InvalidKeyLength(public_key.len()))?;
    VerifyingKey::from_bytes(arr).map_err(|_| Error::InvalidKey)
}

/// Verify an EdDSA JWS compact serialization and return the parsed payload + the
/// `kid` from the header. Returns `None` if the signature doesn't validate, the
/// structure is malformed, or the header has no `kid`.
pub fn verify_jws_eddsa(
    jws: &str,
    public_key: &[u8],
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
    let kid = match header.get("kid").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Ok(None),
    };

    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSignatureLength(sig_bytes.len()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = verifying_key_from_bytes(public_key)?;
    let signed_message = format!("{}.{}", header_b64, payload_b64);
    if verifying_key
        .verify_strict(signed_message.as_bytes(), &signature)
        .is_err()
    {
        return Ok(None);
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;
    Ok(Some((payload, kid)))
}

/// For each (trusted_key, signature) pair: verify the JWS, check that the kid's
/// thumbprint head matches the key's thumbprint, and that the payload's
/// `in.rdrv_aterm_ca` matches `input_hash` and `out.nix` is an object.
/// Returns `(payload_json_string, kid)` for every accepted signature.
pub fn verify_resolved_trace_signatures(
    input_hash: &str,
    signatures: &[String],
    trusted_keys: &[(String, Vec<u8>)],
) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for (_name, key_bytes) in trusted_keys {
        let thumbprint_head = match ed25519_thumbprint(key_bytes) {
            Ok(t) => t[..16].to_string(),
            Err(_) => continue,
        };
        for signature in signatures {
            let (payload, kid) = match verify_jws_eddsa(signature, key_bytes) {
                Ok(Some(v)) => v,
                Ok(None) | Err(_) => continue,
            };
            let received_head = match kid.split_once(':') {
                Some((_, head)) => head,
                None => continue,
            };
            if received_head != thumbprint_head {
                continue;
            }
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
            out.push((payload.to_string(), kid));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_key() -> SigningKey {
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed)
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
        let pk = sk.verifying_key().to_bytes();
        let thumbprint_head = ed25519_thumbprint(&pk).unwrap()[..16].to_string();
        let header = serde_json::json!({
            "alg": "EdDSA",
            "kid": format!("test:{}", thumbprint_head),
        });
        let payload = serde_json::json!({
            "in": { "rdrv_aterm_ca": "abc123" },
            "out": { "nix": { "out": { "path": "/nix/store/x" } } },
        });
        let jws = make_jws(&sk, &header, &payload);

        let trusted = vec![("test".to_string(), pk.to_vec())];
        let results = verify_resolved_trace_signatures("abc123", &[jws.clone()], &trusted).unwrap();
        assert_eq!(results.len(), 1);

        let wrong = verify_resolved_trace_signatures("wronghash", &[jws], &trusted).unwrap();
        assert_eq!(wrong.len(), 0);
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let sk = make_key();
        let pk = sk.verifying_key().to_bytes();
        let thumbprint_head = ed25519_thumbprint(&pk).unwrap()[..16].to_string();
        let header = serde_json::json!({
            "alg": "EdDSA",
            "kid": format!("test:{}", thumbprint_head),
        });
        let payload = serde_json::json!({
            "in": { "rdrv_aterm_ca": "abc123" },
            "out": { "nix": {} },
        });
        let mut jws = make_jws(&sk, &header, &payload);
        // Flip a character in the signature.
        let last = jws.pop().unwrap();
        jws.push(if last == 'A' { 'B' } else { 'A' });

        let trusted = vec![("test".to_string(), pk.to_vec())];
        let results = verify_resolved_trace_signatures("abc123", &[jws], &trusted).unwrap();
        assert_eq!(results.len(), 0);
    }
}
