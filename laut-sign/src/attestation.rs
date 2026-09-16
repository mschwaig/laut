//! Managed-key Sigstore bundles and laut's SLSA provenance profile.
//! See docs/slsa-provenance-v1.md for the wire contract.

use std::collections::HashSet;

use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};

use crate::thumbprint::ed25519_thumbprint;

pub const BUNDLE_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const CA_BUILD_TYPE: &str =
    "https://github.com/mschwaig/laut/blob/main/docs/slsa-provenance-v1.md#ca";
pub const IA_BUILD_TYPE: &str =
    "https://github.com/mschwaig/laut/blob/main/docs/slsa-provenance-v1.md#synthetic-ia";
pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid attestation: {0}")]
    Invalid(&'static str),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("signature: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("key fingerprint: {0}")]
    Thumbprint(#[from] crate::thumbprint::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub media_type: String,
    pub verification_material: VerificationMaterial,
    pub dsse_envelope: Envelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationMaterial {
    pub public_key: PublicKeyHint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tlog_entries: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyHint {
    pub hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    #[serde(default)]
    pub keyid: String,
    pub sig: String,
}

pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    // DSSE accepts either alphabet, with or without padding.
    let normalized = text.replace('-', "+").replace('_', "/");
    Ok(GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
    .decode(normalized)?)
}

pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

pub fn builder_id(key: &VerifyingKey) -> Result<String, Error> {
    Ok(format!(
        "urn:laut:builder:sha256:{}",
        ed25519_thumbprint(key.as_bytes())?
    ))
}

/// Match go-securesystemslib's default DSSE key hint. This is only a hint;
/// consensus and builder IDs still use the full SPKI fingerprint.
pub fn key_hint(key: &VerifyingKey) -> String {
    let ssh = [
        b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20".as_slice(),
        key.as_bytes(),
    ]
    .concat();
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(ssh))
    )
}

impl Bundle {
    pub fn sign(statement: &Value, key: &SigningKey) -> Result<Self, Error> {
        validate_statement(statement, &key.verifying_key())?;
        let payload = serde_json::to_vec(statement)?;
        let signature =
            key.sign_prehashed(Sha512::new_with_prefix(pae(PAYLOAD_TYPE, &payload)), None)?;
        let hint = key_hint(&key.verifying_key());
        Ok(Self {
            media_type: BUNDLE_TYPE.into(),
            verification_material: VerificationMaterial {
                public_key: PublicKeyHint { hint: hint.clone() },
                tlog_entries: Vec::new(),
            },
            dsse_envelope: Envelope {
                payload_type: PAYLOAD_TYPE.into(),
                payload: encode(payload),
                signatures: vec![EnvelopeSignature {
                    keyid: hint,
                    sig: encode(signature.to_bytes()),
                }],
            },
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(pae(
            &self.dsse_envelope.payload_type,
            &decode(&self.dsse_envelope.payload)?,
        ))
    }

    pub fn signature(&self) -> Result<Vec<u8>, Error> {
        if self.dsse_envelope.signatures.len() != 1 {
            return Err(Error::Invalid(
                "a bundle must have exactly one DSSE signature",
            ));
        }
        decode(&self.dsse_envelope.signatures[0].sig)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<Value, Error> {
        if self.media_type != BUNDLE_TYPE
            && self.media_type != "application/vnd.dev.sigstore.bundle+json;version=0.3"
        {
            return Err(Error::Invalid("unsupported bundle version"));
        }
        if self.dsse_envelope.payload_type != PAYLOAD_TYPE {
            return Err(Error::Invalid("unexpected DSSE payload type"));
        }
        let signature = Signature::from_slice(&self.signature()?)?;
        if self.dsse_envelope.signatures[0].keyid != self.verification_material.public_key.hint {
            return Err(Error::Invalid("inconsistent key hints"));
        }
        let payload = decode(&self.dsse_envelope.payload)?;
        key.verify_prehashed_strict(
            Sha512::new_with_prefix(pae(PAYLOAD_TYPE, &payload)),
            None,
            &signature,
        )?;
        let statement = parse_json(&payload)?;
        validate_statement(&statement, key)?;
        Ok(statement)
    }
}

/// Reject duplicate object keys at all depths, including otherwise opaque metadata.
/// Independent verifiers must interpret the same authenticated JSON identically.
pub fn parse_json(bytes: &[u8]) -> Result<Value, Error> {
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON without duplicate keys")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Unique, A::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                        if out.insert(key, value).is_some() {
                            return Err(serde::de::Error::custom("duplicate JSON key"));
                        }
                    }
                    Ok(Unique(Value::Object(out)))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Unique, A::Error> {
                    let mut out = Vec::new();
                    while let Some(Unique(v)) = seq.next_element()? {
                        out.push(v);
                    }
                    Ok(Unique(Value::Array(out)))
                }
                fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    Ok(serde_json::from_slice::<Unique>(bytes)?.0)
}

pub fn parse_bundle(bytes: &[u8]) -> Result<Bundle, Error> {
    if bytes.len() as u64 > MAX_OBJECT_BYTES {
        return Err(Error::Invalid("bundle too large"));
    }
    Ok(serde_json::from_value(parse_json(bytes)?)?)
}

pub fn input_hash(statement: &Value) -> Option<&str> {
    statement
        .pointer("/predicate/buildDefinition/externalParameters/resolvedInputHash")?
        .as_str()
}

pub fn from_ia(statement: &Value) -> bool {
    statement
        .pointer("/predicate/buildDefinition/buildType")
        .and_then(Value::as_str)
        == Some(IA_BUILD_TYPE)
}

pub fn validate_statement(s: &Value, key: &VerifyingKey) -> Result<(), Error> {
    let invalid = || Error::Invalid("statement does not match laut's SLSA v1 profile");
    if s["_type"] != STATEMENT_TYPE || s["predicateType"] != PREDICATE_TYPE {
        return Err(invalid());
    }
    let build = &s["predicate"]["buildDefinition"];
    if build["buildType"] != CA_BUILD_TYPE && build["buildType"] != IA_BUILD_TYPE {
        return Err(invalid());
    }
    let params = build["externalParameters"]
        .as_object()
        .ok_or_else(invalid)?;
    if params.len() != 1 {
        return Err(invalid());
    }
    let hash = input_hash(s).ok_or_else(invalid)?;
    if hash.len() != 32 || nix_compat::nixbase32::decode(hash).map_or(true, |v| v.len() != 20) {
        return Err(invalid());
    }
    if build
        .get("resolvedDependencies")
        .is_some_and(|v| !v.is_null() && v != &json!([]))
    {
        return Err(invalid());
    }
    let run = &s["predicate"]["runDetails"];
    if run["builder"]["id"] != builder_id(key)? {
        return Err(invalid());
    }
    if let Some(versions) = run["builder"].get("version") {
        if !versions.is_null()
            && !versions
                .as_object()
                .is_some_and(|m| m.values().all(Value::is_string))
        {
            return Err(invalid());
        }
    }
    let invocation = run["metadata"]["invocationId"]
        .as_str()
        .ok_or_else(invalid)?;
    if invocation.len() != 32
        || !invocation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let subjects = s["subject"].as_array().ok_or_else(invalid)?;
    if subjects.is_empty() {
        return Err(invalid());
    }
    let mut names = HashSet::new();
    for subject in subjects {
        let name = subject["name"].as_str().ok_or_else(invalid)?;
        if name.is_empty() || !names.insert(name) {
            return Err(invalid());
        }
        let digest = subject["digest"]["sha256"].as_str().ok_or_else(invalid)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        if subject["mediaType"] != "application/x-nix-nar" {
            return Err(invalid());
        }
        let annotations = &subject["annotations"];
        let path = annotations["laut_storePath"].as_str().ok_or_else(invalid)?;
        crate::store_path::extract_store_hash(path).map_err(|_| invalid())?;
        let castore = annotations["laut_castoreEntry"]
            .as_str()
            .ok_or_else(invalid)?;
        if decode(castore)?.is_empty() {
            return Err(invalid());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn create_trace_bundle(
    input_hash: &str,
    debug: Option<&Value>,
    outputs: &Value,
    castore: &Value,
    invocation: u128,
    flavor: Option<&str>,
    version: Option<&str>,
    key: &SigningKey,
    from_ia: bool,
) -> Result<Bundle, Error> {
    let mut subjects = Vec::new();
    for (name, output) in outputs
        .as_object()
        .ok_or(Error::Invalid("outputs must be an object"))?
    {
        let hash = output["hash"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .ok_or(Error::Invalid("expected a SHA-256 NAR hash"))?;
        let digest =
            nix_compat::nixbase32::decode(hash).map_err(|_| Error::Invalid("invalid NAR hash"))?;
        let mut metadata = output
            .as_object()
            .ok_or(Error::Invalid("invalid output"))?
            .clone();
        metadata.remove("path");
        metadata.remove("hash");
        subjects.push(json!({
            "name": name,
            "digest": {"sha256": data_encoding::HEXLOWER.encode(&digest)},
            "mediaType": "application/x-nix-nar",
            "annotations": {
                "laut_storePath": output["path"],
                "laut_castoreEntry": encode(decode(castore[name].as_str().ok_or(Error::Invalid("missing castore entry"))?)?),
                "laut_output": metadata,
            },
        }));
    }
    let mut versions = serde_json::Map::new();
    if let Some(f) = flavor {
        versions.insert("nixFlavor".into(), f.into());
    }
    if let Some(v) = version {
        versions.insert("nixVersion".into(), v.into());
    }
    let mut statement = json!({
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": if from_ia { IA_BUILD_TYPE } else { CA_BUILD_TYPE },
                "externalParameters": {"resolvedInputHash": input_hash},
            },
            "runDetails": {
                "builder": {"id": builder_id(&key.verifying_key())?, "version": versions},
                "metadata": {"invocationId": format!("{invocation:032x}")},
            },
        },
    });
    if let Some(debug) = debug {
        statement["predicate"]["runDetails"]["byproducts"] = json!([{
            "name": "laut-debug-preimage", "mediaType": "application/json",
            "content": encode(serde_json::to_vec(debug)?),
        }]);
    }
    Bundle::sign(&statement, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn fixture() -> (SigningKey, Bundle) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let bundle = create_trace_bundle(&"0".repeat(32), None,
            &json!({"out": {"path": format!("/nix/store/{}-test", "0".repeat(32)), "hash": format!("sha256:{}", "0".repeat(52))}}),
            &json!({"out": "CgA"}), 42, Some("nix"), Some("2.34"), &key, false).unwrap();
        (key, bundle)
    }

    #[test]
    fn round_trip_and_exact_bytes() {
        let (key, bundle) = fixture();
        let statement = bundle.verify(&key.verifying_key()).unwrap();
        assert_eq!(
            input_hash(&statement),
            Some("00000000000000000000000000000000")
        );
        assert_eq!(
            statement["predicate"]["runDetails"]["builder"]["version"]["nixVersion"],
            "2.34"
        );
        let mut altered = bundle.clone();
        altered.dsse_envelope.payload = encode(serde_json::to_vec_pretty(&statement).unwrap());
        assert!(altered.verify(&key.verifying_key()).is_err());
        altered = bundle.clone();
        altered.dsse_envelope.signatures[0].sig =
            encode(key.sign(&bundle.signing_bytes().unwrap()).to_bytes());
        assert!(
            altered.verify(&key.verifying_key()).is_err(),
            "pure Ed25519 is not Ed25519ph"
        );
    }

    #[test]
    fn hints_are_not_authorities_and_type_is_authenticated() {
        let (key, mut bundle) = fixture();
        bundle.dsse_envelope.signatures[0].keyid = "another-name".into();
        assert!(bundle.verify(&key.verifying_key()).is_err());
        bundle.verification_material.public_key.hint = "another-name".into();
        assert!(bundle.verify(&key.verifying_key()).is_ok());
        assert!(
            bundle
                .verify(&SigningKey::from_bytes(&[8; 32]).verifying_key())
                .is_err()
        );
        bundle.dsse_envelope.payload_type = "application/json".into();
        assert!(bundle.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_claims() {
        assert!(parse_json(br#"{"x":{"y":1,"y":2}}"#).is_err());
        let (key, bundle) = fixture();
        let statement = bundle.verify(&key.verifying_key()).unwrap();
        for pointer in [
            "/_type",
            "/predicateType",
            "/subject",
            "/predicate/buildDefinition/buildType",
            "/predicate/buildDefinition/externalParameters",
            "/predicate/runDetails/builder/id",
            "/predicate/runDetails/metadata/invocationId",
        ] {
            let mut bad = statement.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(Bundle::sign(&bad, &key).is_err(), "{pointer}");
        }
        let mut ia = statement.clone();
        ia["predicate"]["buildDefinition"]["buildType"] = IA_BUILD_TYPE.into();
        assert!(from_ia(
            &Bundle::sign(&ia, &key)
                .unwrap()
                .verify(&key.verifying_key())
                .unwrap()
        ));
    }

    #[test]
    fn rejects_duplicate_subjects_dependencies_and_ambiguous_containers() {
        let (key, bundle) = fixture();
        let statement = bundle.verify(&key.verifying_key()).unwrap();
        let mut duplicate = statement.clone();
        duplicate["subject"]
            .as_array_mut()
            .unwrap()
            .push(statement["subject"][0].clone());
        assert!(Bundle::sign(&duplicate, &key).is_err());
        let mut extra = statement.clone();
        extra["predicate"]["buildDefinition"]["externalParameters"]["unresolvedDrv"] =
            "not-allowed".into();
        assert!(Bundle::sign(&extra, &key).is_err());
        extra = statement;
        extra["predicate"]["buildDefinition"]["resolvedDependencies"] =
            json!([{"uri":"unwanted-dependency"}]);
        assert!(Bundle::sign(&extra, &key).is_err());
        let mut container = serde_json::to_value(&bundle).unwrap();
        container["messageSignature"] = json!({});
        assert!(parse_bundle(&serde_json::to_vec(&container).unwrap()).is_err());
        let mut multi = bundle;
        multi
            .dsse_envelope
            .signatures
            .push(multi.dsse_envelope.signatures[0].clone());
        assert!(multi.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn pae_vector_and_base64_variants() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
        for value in ["+/8=", "-_8=", "+/8", "-_8"] {
            assert_eq!(decode(value).unwrap(), [251, 255]);
        }
    }
}
