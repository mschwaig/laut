//! Verification-specific functionality for laut.
//!
//! Splitting this out from `lautr-core` lets the sign-only build of the
//! `lautr` Python module drop the verification code entirely: changes to
//! anything in this crate cannot affect the sign-only build's source tree
//! or its derivation hash.

pub mod backend;
pub mod debug;
pub mod drv_json;
pub mod keyfiles;
pub mod orchestrator;
pub mod signature_verify;
pub mod string_interner;
pub mod types;
pub mod verifier;
