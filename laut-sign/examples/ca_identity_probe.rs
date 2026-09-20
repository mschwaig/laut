//! Diagnostic CA idempotence probe, not a trust-admission check.
//! Usage: ca_identity_probe /nix/store/<hash>-<name> [external-reference ...]
//! References must be absolute native store paths, excluding the output itself.

use std::collections::HashMap;
use std::error::Error;
use std::ffi::OsString;
use std::path::Path;

use laut_compat::content_hash::{create_castore_entry, rewrite_to_ca_pass1, rewrite_to_ca_pass2};
use nix_compat::{nixbase32, store_path::StorePath};
use serde_json::{Value, json};

fn probe(mut args: impl Iterator<Item = OsString>) -> Result<Value, Box<dyn Error>> {
    let output = args
        .next()
        .ok_or("usage: ca_identity_probe /nix/store/<hash>-<name> [external-reference ...]")?;
    let native = StorePath::<String>::from_absolute_path(output.as_encoded_bytes())?;
    let mut references = Vec::new();
    for arg in args {
        let reference = StorePath::<String>::from_absolute_path(arg.as_encoded_bytes())?;
        if reference == native {
            return Err("external references must exclude the output itself".into());
        }
        references.push(reference.to_absolute_path());
    }
    references.sort();
    references.dedup();

    let path = Path::new(&output);
    let self_hash = nixbase32::encode(native.digest());
    let ca = rewrite_to_ca_pass1(
        path,
        native.name(),
        &HashMap::new(),
        &self_hash,
        &references,
    )?;
    let rewrites = HashMap::from([(self_hash, nixbase32::encode(ca.digest()))]);
    let rewritten = rewrite_to_ca_pass2(path, &rewrites)?;
    let native_castore_entry = create_castore_entry(path)?;

    Ok(json!({
        "path": ca.to_absolute_path(),
        "nar_hash": data_encoding::HEXLOWER.encode(rewritten.nar_hash.digest_as_bytes()),
        "nar_size": rewritten.nar_size,
        "castore_entry": rewritten.castore_entry_base64,
        "native_castore_entry": native_castore_entry,
    }))
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", probe(std::env::args_os().skip(1))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT: &str = "/nix/store/00000000000000000000000000000000-probe";

    #[test]
    fn missing_output_is_an_error() {
        let error = probe(std::iter::empty()).unwrap_err();
        assert!(error.to_string().contains("usage:"));
    }

    #[test]
    fn malformed_output_and_reference_paths_are_errors() {
        for invalid in [
            "00000000000000000000000000000000-probe",
            "/tmp/00000000000000000000000000000000-probe",
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-probe",
            "/nix/store/00000000000000000000000000000000-probe/child",
        ] {
            for args in [vec![invalid], vec![OUTPUT, invalid]] {
                let error = probe(args.into_iter().map(OsString::from)).unwrap_err();
                assert!(error.is::<nix_compat::store_path::Error>(), "{error}");
            }
        }
    }

    #[test]
    fn self_reference_is_an_error() {
        let error = probe([OUTPUT, OUTPUT].into_iter().map(OsString::from)).unwrap_err();
        assert!(error.to_string().contains("exclude the output itself"));
    }
}
