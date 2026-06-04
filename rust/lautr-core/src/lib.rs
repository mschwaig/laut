//! Core functionality shared by signing and verification.
//!
//! This crate holds the pieces that are needed regardless of which side of the
//! signing/verification boundary the caller is on: derivation-path computation,
//! content hashing, the constructive-trace resolved-input-hash routine, and the
//! ed25519 JWK thumbprint that signers use to produce a `kid` and verifiers
//! use to match a signature against a trusted key.
//!
//! Nothing in this crate links against PyO3; the PyO3 bindings live in
//! `lautr-py`. Verification-specific logic lives in `lautr-verify`.

pub mod constructive_trace;
pub mod content_hash;
pub mod derivation;
pub mod keyfiles;
pub mod store_path;
pub mod thumbprint;
