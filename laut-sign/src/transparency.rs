//! Rekor v2 submission and offline inclusion verification for managed keys.
//! Shared because publishers must authenticate the log's response too.

use crate::attestation::{self, Bundle, decode, encode, parse_json};
use ed25519_dalek::{Signature, VerifyingKey};
use p256::{
    ecdsa::{Signature as EcSignature, VerifyingKey as EcKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{io::Read, path::Path, time::Duration};

const MAX_LOG_RESPONSE: u64 = 2 * 1024 * 1024;
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("transparency: {0}")]
    Invalid(&'static str),
    #[error("attestation: {0}")]
    Attestation(#[from] attestation::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Rekor request failed: {0}")]
    Http(String),
}

#[derive(Debug, Clone)]
enum LogKey {
    Ed25519(VerifyingKey),
    P256(EcKey),
}

#[derive(Debug, Clone)]
struct Log {
    url: String,
    origin: String,
    id: Vec<u8>,
    key: LogKey,
}

/// Explicitly supplied Sigstore TrustedRoot log material. Never fetched implicitly.
#[derive(Debug, Clone)]
pub struct LogTrust {
    logs: Vec<Log>,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub url: String,
    pub trust: LogTrust,
}

fn text<'a>(v: &'a Value, pointer: &str) -> Result<&'a str, Error> {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(Error::Invalid("missing or incorrectly typed log field"))
}

pub fn ed25519_spki(key: &VerifyingKey) -> Vec<u8> {
    [ED25519_SPKI_PREFIX, key.as_bytes()].concat()
}

impl LogTrust {
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        Self::from_json(&std::fs::read(path)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let root = parse_json(bytes)?;
        if root["mediaType"] != "application/vnd.dev.sigstore.trustedroot+json;version=0.1" {
            return Err(Error::Invalid("unsupported TrustedRoot media type"));
        }
        let entries = root["tlogs"]
            .as_array()
            .ok_or(Error::Invalid("TrustedRoot has no logs"))?;
        let mut logs = Vec::new();
        for entry in entries {
            let url = text(entry, "/baseUrl")?.trim_end_matches('/').to_owned();
            let origin = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .ok_or(Error::Invalid("log URL must use HTTP(S)"))?
                .to_owned();
            if origin.is_empty()
                || origin
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '+' | '?' | '#' | '@'))
            {
                return Err(Error::Invalid("invalid log origin"));
            }
            let der = decode(text(entry, "/publicKey/rawBytes")?)?;
            let (key, id) = match text(entry, "/publicKey/keyDetails")? {
                "PKIX_ED25519" => {
                    let raw: &[u8; 32] = der
                        .strip_prefix(ED25519_SPKI_PREFIX)
                        .and_then(|b| b.try_into().ok())
                        .ok_or(Error::Invalid("invalid Ed25519 log SPKI"))?;
                    let key = VerifyingKey::from_bytes(raw)
                        .map_err(|_| Error::Invalid("invalid log key"))?;
                    let id = Sha256::digest([origin.as_bytes(), b"\n\x01", raw].concat()).to_vec();
                    (LogKey::Ed25519(key), id)
                }
                "PKIX_ECDSA_P256_SHA_256" => {
                    let key = EcKey::from_public_key_der(&der)
                        .map_err(|_| Error::Invalid("invalid P-256 log SPKI"))?;
                    (LogKey::P256(key), Sha256::digest(&der).to_vec())
                }
                _ => return Err(Error::Invalid("unsupported checkpoint signing algorithm")),
            };
            if entry["hashAlgorithm"] != "SHA2_256" {
                return Err(Error::Invalid("unsupported Merkle hash"));
            }
            for pointer in ["/logId/keyId", "/checkpointKeyId/keyId"] {
                if let Some(value) = entry.pointer(pointer) {
                    if decode(value.as_str().ok_or(Error::Invalid("invalid log ID"))?)? != id {
                        return Err(Error::Invalid("log ID does not match origin and key"));
                    }
                }
            }
            logs.push(Log {
                url,
                origin,
                id,
                key,
            });
        }
        if logs.is_empty() {
            return Err(Error::Invalid("TrustedRoot has no logs"));
        }
        Ok(Self { logs })
    }

    /// At least one inclusion proof must verify under an explicitly trusted log.
    pub fn verify(&self, bundle: &Bundle, signer: &VerifyingKey) -> Result<(), Error> {
        if bundle.verification_material.tlog_entries.len() > 32 {
            return Err(Error::Invalid("too many log entries"));
        }
        for entry in &bundle.verification_material.tlog_entries {
            for log in &self.logs {
                if log.verify_entry(entry, bundle, signer).is_ok() {
                    return Ok(());
                }
            }
        }
        Err(Error::Invalid(
            "no valid inclusion proof from a trusted log",
        ))
    }
}

fn signed_metadata(bundle: &Bundle, key: &VerifyingKey) -> Result<Value, Error> {
    Ok(json!({
        "data": {"algorithm": "SHA2_512", "digest": encode(Sha512::digest(bundle.signing_bytes()?))},
        "signature": {
            "content": encode(bundle.signature()?),
            "verifier": {"keyDetails": "PKIX_ED25519_PH", "publicKey": {"rawBytes": encode(ed25519_spki(key))}},
        },
    }))
}

impl Log {
    fn verify_entry(
        &self,
        entry: &Value,
        bundle: &Bundle,
        key: &VerifyingKey,
    ) -> Result<(), Error> {
        if decode(text(entry, "/logId/keyId")?)? != self.id
            || entry["kindVersion"] != json!({"kind":"hashedrekord", "version":"0.0.2"})
        {
            return Err(Error::Invalid("unexpected log or entry type"));
        }
        let body = decode(text(entry, "/canonicalizedBody")?)?;
        if body.len() as u64 > MAX_LOG_RESPONSE {
            return Err(Error::Invalid("entry too large"));
        }
        let expected = json!({"kind":"hashedrekord", "apiVersion":"0.0.2", "spec":{"hashedRekordV002": signed_metadata(bundle, key)?}});
        if parse_json(&body)? != expected {
            return Err(Error::Invalid(
                "log entry does not bind this envelope, signature and key",
            ));
        }
        let checkpoint = text(entry, "/inclusionProof/checkpoint/envelope")?;
        let (size, root) = self.verify_checkpoint(checkpoint)?;
        let index = decimal(text(entry, "/logIndex")?)?;
        let hashes = entry
            .pointer("/inclusionProof/hashes")
            .and_then(Value::as_array)
            .ok_or(Error::Invalid("missing inclusion path"))?;
        if hashes.len() > 63 {
            return Err(Error::Invalid("inclusion path too long"));
        }
        let hashes: Vec<Vec<u8>> = hashes
            .iter()
            .map(|h| {
                Ok(decode(
                    h.as_str().ok_or(Error::Invalid("invalid proof hash"))?,
                )?)
            })
            .collect::<Result<_, Error>>()?;
        // Only the authenticated checkpoint supplies size/root; v2 duplicates
        // these in untrusted convenience fields that are intentionally ignored.
        if !verify_inclusion(&body, index, size, &hashes, &root) {
            return Err(Error::Invalid("invalid Merkle inclusion proof"));
        }
        Ok(())
    }

    fn verify_checkpoint(&self, checkpoint: &str) -> Result<(u64, Vec<u8>), Error> {
        let (body, signatures) = checkpoint
            .split_once("\n\n")
            .ok_or(Error::Invalid("malformed checkpoint"))?;
        let signed = format!("{body}\n");
        let lines: Vec<_> = body.split('\n').collect();
        if lines.len() < 3 || lines.iter().any(|s| s.is_empty()) || lines[0] != self.origin {
            return Err(Error::Invalid("unexpected checkpoint origin or layout"));
        }
        let mut authenticated = false;
        for line in signatures.lines() {
            let Some(rest) = line.strip_prefix("\u{2014} ") else {
                continue;
            };
            let Some((name, sig)) = rest.split_once(' ') else {
                continue;
            };
            if name != self.origin {
                continue;
            }
            let Ok(signature) = decode(sig) else { continue };
            if signature.len() < 5 || signature[..4] != self.id[..4] {
                continue;
            }
            authenticated |= match &self.key {
                LogKey::Ed25519(key) => Signature::from_slice(&signature[4..])
                    .is_ok_and(|sig| key.verify_strict(signed.as_bytes(), &sig).is_ok()),
                LogKey::P256(key) => EcSignature::from_der(&signature[4..])
                    .is_ok_and(|sig| key.verify(signed.as_bytes(), &sig).is_ok()),
            };
        }
        if !authenticated {
            return Err(Error::Invalid("invalid checkpoint signature"));
        }
        let size = decimal(lines[1])?;
        let root = decode(lines[2])?;
        if root.len() != 32 || size == 0 {
            return Err(Error::Invalid("invalid checkpoint tree"));
        }
        Ok((size, root))
    }
}

fn decimal(value: &str) -> Result<u64, Error> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(Error::Invalid("invalid tree index/size"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::Invalid("tree index/size out of range"))
}

fn leaf_hash(body: &[u8]) -> Vec<u8> {
    Sha256::digest([b"\x00", body].concat()).to_vec()
}
fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    Sha256::digest([b"\x01", left, right].concat()).to_vec()
}

fn verify_inclusion(body: &[u8], index: u64, size: u64, path: &[Vec<u8>], root: &[u8]) -> bool {
    if size == 0 || index >= size || path.iter().any(|h| h.len() != 32) {
        return false;
    }
    let (mut position, mut last) = (index, size - 1);
    let mut hash = leaf_hash(body);
    for sibling in path {
        if last == 0 {
            return false;
        }
        if position & 1 == 1 || position == last {
            hash = node_hash(sibling, &hash);
            while position != 0 && position & 1 == 0 {
                position >>= 1;
                last >>= 1;
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        position >>= 1;
        last >>= 1;
    }
    last == 0 && hash == root
}

pub fn submit(bundle: &mut Bundle, key: &VerifyingKey, config: &LogConfig) -> Result<(), Error> {
    bundle.verify(key)?;
    let base = config.url.trim_end_matches('/');
    let log = config
        .trust
        .logs
        .iter()
        .find(|l| l.url == base)
        .ok_or(Error::Invalid("Rekor URL not in configured trust root"))?;
    let metadata = signed_metadata(bundle, key)?;
    let request = json!({"hashedRekordRequestV002": {"digest": metadata["data"]["digest"], "signature": metadata["signature"]}}).to_string();
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .redirects(0)
        .build();
    let url = format!("{base}/api/v2/log/entries");
    for attempt in 0..3 {
        match agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&request)
        {
            Ok(response) => {
                let mut body = Vec::new();
                response
                    .into_reader()
                    .take(MAX_LOG_RESPONSE + 1)
                    .read_to_end(&mut body)?;
                if body.len() as u64 > MAX_LOG_RESPONSE {
                    return Err(Error::Invalid("log response too large"));
                }
                let entry = parse_json(&body)?;
                log.verify_entry(&entry, bundle, key)?;
                bundle.verification_material.tlog_entries.push(entry);
                return Ok(());
            }
            Err(e) => {
                let retry = match &e {
                    ureq::Error::Transport(_) => true,
                    ureq::Error::Status(code, _) => *code == 429 || *code >= 500,
                };
                if !retry || attempt == 2 {
                    return Err(Error::Http(e.to_string()));
                }
                std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
            }
        }
    }
    unreachable!("bounded retry loop returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn tree(leaves: &[Vec<u8>], index: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        if leaves.len() == 1 {
            return (leaf_hash(&leaves[0]), vec![]);
        }
        let split = 1 << (usize::BITS - 1 - (leaves.len() - 1).leading_zeros());
        let (left, mut lp) = tree(&leaves[..split], index.min(split - 1));
        let (right, mut rp) = tree(&leaves[split..], index.saturating_sub(split));
        let proof = if index < split {
            lp.push(right.clone());
            lp
        } else {
            rp.push(left.clone());
            rp
        };
        (node_hash(&left, &right), proof)
    }

    #[test]
    fn inclusion_all_positions_and_unbalanced_trees() {
        for size in 1..70 {
            let leaves: Vec<_> = (0..size)
                .map(|i| format!("leaf-{i}").into_bytes())
                .collect();
            for index in 0..size {
                let (root, proof) = tree(&leaves, index);
                assert!(
                    verify_inclusion(&leaves[index], index as u64, size as u64, &proof, &root),
                    "{index}/{size}"
                );
                assert!(!verify_inclusion(
                    b"wrong",
                    index as u64,
                    size as u64,
                    &proof,
                    &root
                ));
                if !proof.is_empty() {
                    assert!(!verify_inclusion(
                        &leaves[index],
                        index as u64,
                        size as u64,
                        &proof[1..],
                        &root
                    ));
                }
                let mut extra = proof.clone();
                extra.push(vec![0; 32]);
                assert!(!verify_inclusion(
                    &leaves[index],
                    index as u64,
                    size as u64,
                    &extra,
                    &root
                ));
            }
        }
    }

    #[test]
    fn p256_checkpoints_extensions_and_unknown_cosignatures() {
        use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
        let key = SigningKey::from_slice(&[11; 32]).unwrap();
        let der = key.verifying_key().to_public_key_der().unwrap();
        let id = Sha256::digest(der.as_bytes());
        let root = json!({"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs":[{"baseUrl":"https://log.example:4444/path", "hashAlgorithm":"SHA2_256",
                "logId":{"keyId":encode(id)},
                "publicKey":{"keyDetails":"PKIX_ECDSA_P256_SHA_256", "rawBytes":encode(der.as_bytes())}}]});
        let trust = LogTrust::from_json(root.to_string().as_bytes()).unwrap();
        let body = format!(
            "log.example:4444/path\n17\n{}\nopaque extension\n",
            encode([1; 32])
        );
        let sig: EcSignature = key.sign(body.as_bytes());
        let checkpoint = format!(
            "{body}\n\u{2014} unknown {}\n\u{2014} log.example:4444/path {}\n",
            encode([0; 68]),
            encode([&id[..4], sig.to_der().as_bytes()].concat())
        );
        assert_eq!(
            trust.logs[0].verify_checkpoint(&checkpoint).unwrap(),
            (17, vec![1; 32])
        );
        assert!(
            trust.logs[0]
                .verify_checkpoint(&checkpoint.replace("opaque", "tampered"))
                .is_err()
        );
        assert!(
            trust.logs[0]
                .verify_checkpoint(&checkpoint.replace("\n17\n", "\n18\n"))
                .is_err()
        );
        let mut bad_root = root;
        bad_root["tlogs"][0]["logId"]["keyId"] = encode([0; 32]).into();
        assert!(LogTrust::from_json(bad_root.to_string().as_bytes()).is_err());
        for number in ["-1", "+1", "01", "", "9223372036854775808"] {
            assert!(decimal(number).is_err());
        }
    }

    #[test]
    fn validates_signed_checkpoint_and_all_entry_bindings() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let log_key = SigningKey::from_bytes(&[9; 32]);
        let root = json!({"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs":[{"baseUrl":"http://log", "hashAlgorithm":"SHA2_256", "publicKey":{
                "keyDetails":"PKIX_ED25519", "rawBytes":encode(ed25519_spki(&log_key.verifying_key()))}}]});
        let trust = LogTrust::from_json(root.to_string().as_bytes()).unwrap();
        let log = &trust.logs[0];
        let mut bundle = attestation::create_trace_bundle(&"0".repeat(32), None,
            &json!({"out":{"path":format!("/nix/store/{}-test", "0".repeat(32)),"hash":format!("sha256:{}", "0".repeat(52))}}),
            &json!({"out":"CgA"}), 42, None, None, &signer, false).unwrap();
        let body = json!({"kind":"hashedrekord","apiVersion":"0.0.2","spec":{"hashedRekordV002":signed_metadata(&bundle, &signer.verifying_key()).unwrap()}}).to_string();
        let head = format!("log\n1\n{}\n", encode(leaf_hash(body.as_bytes())));
        let sig = log_key.sign(head.as_bytes());
        let checkpoint = format!(
            "{head}\n\u{2014} log {}\n",
            encode([&log.id[..4], &sig.to_bytes()].concat())
        );
        let entry = json!({"logId":{"keyId":encode(&log.id)},"kindVersion":{"kind":"hashedrekord","version":"0.0.2"},
            "canonicalizedBody":encode(&body),"logIndex":"0","inclusionProof":{"hashes":[],"checkpoint":{"envelope":checkpoint}}});
        bundle
            .verification_material
            .tlog_entries
            .push(entry.clone());
        trust.verify(&bundle, &signer.verifying_key()).unwrap();
        for pointer in [
            "/logIndex",
            "/logId/keyId",
            "/canonicalizedBody",
            "/kindVersion/version",
            "/inclusionProof/checkpoint/envelope",
        ] {
            let mut bad = entry.clone();
            *bad.pointer_mut(pointer).unwrap() = "bad".into();
            assert!(
                log.verify_entry(&bad, &bundle, &signer.verifying_key())
                    .is_err(),
                "{pointer}"
            );
        }
        let mut wrong_binding = parse_json(body.as_bytes()).unwrap();
        wrong_binding["spec"]["hashedRekordV002"]["data"]["digest"] = encode([0; 64]).into();
        let mut wrong_entry = entry.clone();
        wrong_entry["canonicalizedBody"] = encode(wrong_binding.to_string()).into();
        assert!(
            log.verify_entry(&wrong_entry, &bundle, &signer.verifying_key())
                .is_err()
        );
        bundle.verification_material.tlog_entries.clear();
        assert!(trust.verify(&bundle, &signer.verifying_key()).is_err());
    }
}
