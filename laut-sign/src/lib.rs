//! Core functionality shared by signing and verification.
//!
//! This crate holds the pieces that are needed regardless of which side of the
//! signing/verification boundary the caller is on: derivation-path computation,
//! content hashing, the constructive-trace resolved-input-hash routine, and the
//! ed25519 JWK thumbprint that signers use to produce a `kid` and verifiers
//! use to match a signature against a trusted key.
//!
//! Verification-specific logic lives in `laut-verify`.

pub mod constructive_trace;
pub mod content_hash;
pub mod derivation;
pub mod drv_json;
pub mod http_cache;
pub mod keyfiles;
pub mod nix_cmd;
pub mod sign;
pub mod store_path;
pub mod thumbprint;
