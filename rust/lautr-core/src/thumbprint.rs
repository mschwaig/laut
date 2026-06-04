//! RFC 7638-style JWK thumbprint for ed25519 keys.
//!
//! Lives in core because signers compute it to populate `kid` at sign time,
//! and verifiers compute it to match a signature's `kid` against a trusted
//! key at verify time.

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
}

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub fn ed25519_thumbprint(public_key: &[u8]) -> Result<String, Error> {
    if public_key.len() != 32 {
        return Err(Error::InvalidKeyLength(public_key.len()));
    }
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    let digest = Sha256::digest(&spki);
    Ok(HEXLOWER.encode(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_known_format() {
        let pk = [0u8; 32];
        let t = ed25519_thumbprint(&pk).unwrap();
        assert_eq!(t.len(), 64);
    }
}
