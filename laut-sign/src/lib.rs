//! Core functionality shared by signing and verification.
//!
//! This crate holds the pieces that are needed regardless of which side of the
//! signing/verification boundary the caller is on: derivation-path computation,
//! content hashing, the constructive-trace resolved-input-hash routine, and the
//! Ed25519 SPKI fingerprint that identifies configured signer authorities.
//!
//! Verification-specific logic lives in `laut-verify`.

pub mod attestation;
pub mod constructive_trace;
pub mod content_hash;
pub mod derivation;
pub mod drv_json;
pub mod http_cache;
pub mod ia_closure;
pub mod keyfiles;
pub mod nix_cmd;
pub mod sign;
pub mod store_path;
pub mod thumbprint;
pub mod transparency;
