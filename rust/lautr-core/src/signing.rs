//! Build a laut trace JWS (compact serialization) and sign it with ed25519.
//!
//! The companion verifier lives in `lautr-verify::signature_verify`; the wire
//! format here is the JWS this signer produces is what that verifier accepts.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};

use crate::thumbprint::{self, ed25519_thumbprint};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Thumbprint(#[from] thumbprint::Error),
}

/// Build the laut trace JWS for one resolved derivation and sign it.
///
/// `castore_outputs` and `output_hashes` are passed as already-built JSON
/// values so the caller (Python orchestrator, tests with mock castore output,
/// or a future Rust orchestrator) can shape them without touching this code.
pub fn create_trace_signature(
    input_hash: &str,
    debug_data: Option<&Value>,
    output_hashes: &Value,
    castore_outputs: &Value,
    rebuild_id: u32,
    builder_nix_flavor: Option<&str>,
    builder_nix_version: Option<&str>,
    key_name: &str,
    seed: &[u8; 32],
) -> Result<String, Error> {
    let signing_key = SigningKey::from_bytes(seed);
    let public = signing_key.verifying_key().to_bytes();
    let thumbprint = ed25519_thumbprint(&public)?;

    let header = json!({
        "type": "laut",
        "alg": "EdDSA",
        "crv": "Ed25519",
        "v": "2",
        "kid": format!("{}:{}", key_name, &thumbprint[..16]),
        "detachHash": "nix-ca-path",
    });

    let mut in_obj: Map<String, Value> = Map::new();
    in_obj.insert("rdrv_aterm_ca".into(), Value::String(input_hash.to_owned()));
    if let Some(debug) = debug_data {
        in_obj.insert("debug".into(), debug.clone());
    }

    let mut builder_obj: Map<String, Value> = Map::new();
    builder_obj.insert("rebuild_id".into(), json!(rebuild_id));
    builder_obj.insert("store_root".into(), Value::String("/nix/store".into()));
    if let Some(flavor) = builder_nix_flavor {
        builder_obj.insert("nix_flavor".into(), Value::String(flavor.to_owned()));
    }
    if let Some(version) = builder_nix_version {
        builder_obj.insert("nix_version".into(), Value::String(version.to_owned()));
    }

    let payload = json!({
        "in": Value::Object(in_obj),
        "out": {
            "castore-entry": castore_outputs,
            "nix": output_hashes,
        },
        "builder": Value::Object(builder_obj),
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{}.{}", signing_input, sig_b64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn split_jws(jws: &str) -> (Value, Value, [u8; 64]) {
        let mut parts = jws.split('.');
        let header_b64 = parts.next().unwrap();
        let payload_b64 = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();
        assert!(parts.next().is_none());
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        (header, payload, sig)
    }

    #[test]
    fn round_trip_signs_and_verifies() {
        let seed = [7u8; 32];
        let output_hashes = json!({
            "out": { "path": "/nix/store/x-foo", "hash": "sha256:0000" }
        });
        let castore_outputs = json!({ "out": "abc123base64url" });

        let jws = create_trace_signature(
            "input-hash-here",
            None,
            &output_hashes,
            &castore_outputs,
            42,
            Some("lix"),
            Some("2.91.1"),
            "builderA",
            &seed,
        )
        .unwrap();

        let (header, payload, sig_bytes) = split_jws(&jws);

        // Header is the expected shape, kid carries the truncated thumbprint.
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["type"], "laut");
        let kid = header["kid"].as_str().unwrap();
        let (name, head) = kid.split_once(':').unwrap();
        assert_eq!(name, "builderA");
        let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(ed25519_thumbprint(&pk).unwrap()[..16], *head);

        // Payload roundtrips its inputs verbatim.
        assert_eq!(payload["in"]["rdrv_aterm_ca"], "input-hash-here");
        assert!(payload["in"].get("debug").is_none());
        assert_eq!(payload["builder"]["rebuild_id"], 42);
        assert_eq!(payload["builder"]["store_root"], "/nix/store");
        assert_eq!(payload["builder"]["nix_flavor"], "lix");
        assert_eq!(payload["builder"]["nix_version"], "2.91.1");
        assert_eq!(payload["out"]["castore-entry"], castore_outputs);
        assert_eq!(payload["out"]["nix"], output_hashes);

        // Signature verifies against the recomputed signing input.
        let header_b64 = jws.split('.').next().unwrap();
        let payload_b64 = jws.split('.').nth(1).unwrap();
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature = Signature::from_bytes(&sig_bytes);
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify(signing_input.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn debug_block_included_when_provided() {
        let seed = [3u8; 32];
        let debug = json!({
            "drv_name": "hello",
            "rdrv_path": "/nix/store/yyy.drv",
        });
        let jws = create_trace_signature(
            "h",
            Some(&debug),
            &json!({}),
            &json!({}),
            0,
            None,
            None,
            "k",
            &seed,
        )
        .unwrap();
        let (_, payload, _) = split_jws(&jws);
        assert_eq!(payload["in"]["debug"], debug);
        assert!(payload["builder"].get("nix_flavor").is_none());
        assert!(payload["builder"].get("nix_version").is_none());
    }
}
