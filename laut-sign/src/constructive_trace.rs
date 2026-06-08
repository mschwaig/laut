//! Compute the resolved-input-hash drv path for an unresolved derivation, given a
//! resolution map for each of its input derivations' outputs.
//!
//! We parse with snix's non-validating parser, edit the `Derivation` struct
//! (drop `inputDrvs`, fold the resolved content-hash paths into `inputSrcs`),
//! serialize back to ATerm, replace upstream placeholders throughout the bytes,
//! and hand the result to [`calculate_derivation_path_from_aterm`] for the
//! final hash.

use std::collections::HashMap;

use nix_compat::derivation::{calculate_derivation_path_from_aterm, Derivation};
use nix_compat::store_path::{self, StorePath};

/// Map of unresolved input drv path -> output name -> resolved content-hash path.
pub type Resolutions = HashMap<String, HashMap<String, String>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse derivation ATerm: {0}")]
    Parse(String),
    #[error("{0}")]
    InvalidContentHashPath(String),
    #[error("failed to compute placeholder: {0}")]
    Placeholder(String),
    #[error("failed to compute resolved drv path: {0}")]
    Path(String),
    #[error("{0}")]
    MissingResolution(String),
    #[error("resolved ATerm bytes are not valid UTF-8")]
    NonUtf8Aterm,
}

/// Compute `(resolved_drv_path, resolved_aterm)` for `drv_aterm` under `resolutions`.
///
/// An empty `resolutions` is the "nothing to substitute" case (used for FODs and
/// for derivations whose `inputDrvs` was already empty). In that case the input
/// bytes are returned unchanged and the drv path is computed from them directly.
pub fn compute_resolved_input_hash(
    drv_name: &str,
    drv_aterm: &[u8],
    resolutions: &Resolutions,
) -> Result<(String, String), Error> {
    if resolutions.is_empty() {
        let path = calculate_derivation_path_from_aterm(drv_name, drv_aterm)
            .map_err(|e| Error::Path(format!("{:?}", e)))?;
        let aterm = std::str::from_utf8(drv_aterm)
            .map_err(|_| Error::NonUtf8Aterm)?
            .to_owned();
        return Ok((path, aterm));
    }

    let mut drv = Derivation::from_aterm_bytes_unchecked(drv_aterm)
        .map_err(|e| Error::Parse(format!("{:?}", e)))?;

    // Walk input_derivations in one pass, collecting:
    //   - resolved content-hash paths to fold into input_sources
    //   - placeholder/replacement pairs to apply post-serialize
    let mut new_input_sources: Vec<StorePath<String>> = Vec::new();
    let mut substitutions: Vec<(String, String)> = Vec::new();

    for (input_drv_sp, output_names) in &drv.input_derivations {
        let input_drv_path = input_drv_sp.to_absolute_path();
        let outputs_map = resolutions.get(&input_drv_path).ok_or_else(|| {
            Error::MissingResolution(format!(
                "no resolution provided for input derivation {}",
                input_drv_path
            ))
        })?;

        for output_name in output_names {
            let content_hash_path = outputs_map.get(output_name).ok_or_else(|| {
                Error::MissingResolution(format!(
                    "no resolution provided for output {}!{}",
                    input_drv_path, output_name
                ))
            })?;

            let store_path = StorePath::from_absolute_path(content_hash_path.as_bytes())
                .map_err(|e| {
                    Error::InvalidContentHashPath(format!(
                        "resolved content-hash path {} is not a valid store path: {:?}",
                        content_hash_path, e
                    ))
                })?;
            new_input_sources.push(store_path);

            let placeholder = store_path::hash_upstream_placeholder(
                "/nix/store/",
                &input_drv_path,
                output_name,
            )
            .map_err(Error::Placeholder)?;
            substitutions.push((placeholder, content_hash_path.clone()));
        }
    }

    drv.input_derivations.clear();
    for sp in new_input_sources {
        drv.input_sources.insert(sp);
    }

    let mut aterm = drv.to_aterm_bytes();
    for (placeholder, content_hash) in &substitutions {
        aterm = replace_bytes(&aterm, placeholder.as_bytes(), content_hash.as_bytes());
    }

    let resolved_path = calculate_derivation_path_from_aterm(drv_name, &aterm)
        .map_err(|e| Error::Path(format!("{:?}", e)))?;
    let aterm_str = String::from_utf8(aterm).map_err(|_| Error::NonUtf8Aterm)?;

    Ok((resolved_path, aterm_str))
}

/// IA variant of [`compute_resolved_input_hash`]: take an input-addressed drv
/// ATerm, replace its input-addressed store paths (input drvs' outputs and the
/// drv's own outputs) with the supplied synthetic CA equivalents, clear
/// `inputDrvs`, fold the input drv outputs into `inputSrcs`, and recompute the
/// drv path.
///
/// The CA pipeline (above) substitutes upstream hash-placeholders; IA inputs
/// reference concrete IA paths instead, so callers pre-compute the
/// IA→synthetic-CA mapping for every store path that appears in the ATerm
/// (input drvs' outputs + this drv's own outputs) and pass it in
/// `substitutions`.
///
/// `input_drv_outputs_synthetic_ca` is the set of synthetic CA paths that
/// previously sat in `inputDrvs`; they get folded into `inputSrcs` so the
/// resulting ATerm looks structurally identical to a CA-resolved drv.
pub fn compute_resolved_input_hash_ia(
    drv_name: &str,
    drv_aterm: &[u8],
    input_drv_outputs_synthetic_ca: Vec<StorePath<String>>,
    substitutions: &HashMap<String, String>,
) -> Result<(String, String), Error> {
    let mut drv = Derivation::from_aterm_bytes_unchecked(drv_aterm)
        .map_err(|e| Error::Parse(format!("{:?}", e)))?;

    drv.input_derivations.clear();
    for sp in input_drv_outputs_synthetic_ca {
        drv.input_sources.insert(sp);
    }

    let mut aterm = drv.to_aterm_bytes();
    for (ia_path, synthetic_ca_path) in substitutions {
        aterm = replace_bytes(&aterm, ia_path.as_bytes(), synthetic_ca_path.as_bytes());
    }

    let resolved_path = calculate_derivation_path_from_aterm(drv_name, &aterm)
        .map_err(|e| Error::Path(format!("{:?}", e)))?;
    let aterm_str = String::from_utf8(aterm).map_err(|_| Error::NonUtf8Aterm)?;

    Ok((resolved_path, aterm_str))
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out.extend_from_slice(&haystack[i..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // 32-char nixbase32-valid (alphabet excludes e, o, t, u).
    const SELF_IA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SELF_CA: &str = "dddddddddddddddddddddddddddddddd";
    const INPUT_DRV: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const INPUT_OUT_IA: &str = "cccccccccccccccccccccccccccccccc";
    const INPUT_OUT_CA: &str = "ffffffffffffffffffffffffffffffff";

    fn synthetic_ia_aterm() -> String {
        // Minimal IA-style drv: one output, one input drv with one output, no
        // sources, env carries the self output path and a dep path.
        format!(
            concat!(
                r#"Derive([("out","/nix/store/{self_ia}-self","","")],"#,
                r#"[("/nix/store/{inp_drv}-inp.drv",["out"])],"#,
                r#"[],"#,
                r#""x86_64-linux","/bin/sh",[],"#,
                r#"[("dep","/nix/store/{inp_out_ia}-input-out"),("#,
                r#""out","/nix/store/{self_ia}-self")])"#,
            ),
            self_ia = SELF_IA,
            inp_drv = INPUT_DRV,
            inp_out_ia = INPUT_OUT_IA,
        )
    }

    #[test]
    fn ia_substitutes_self_and_input_drv_output_paths() {
        let aterm = synthetic_ia_aterm();

        let mut subs: HashMap<String, String> = HashMap::new();
        subs.insert(
            format!("/nix/store/{}-self", SELF_IA),
            format!("/nix/store/{}-self", SELF_CA),
        );
        subs.insert(
            format!("/nix/store/{}-input-out", INPUT_OUT_IA),
            format!("/nix/store/{}-input-out", INPUT_OUT_CA),
        );

        let input_sources = vec![
            StorePath::<String>::from_absolute_path(
                format!("/nix/store/{}-input-out", INPUT_OUT_CA).as_bytes(),
            )
            .expect("valid CA path"),
        ];

        let (drv_path, new_aterm) =
            compute_resolved_input_hash_ia("self", aterm.as_bytes(), input_sources, &subs)
                .expect("substitution succeeds");

        assert!(drv_path.ends_with("-self.drv"));
        // IA hashes are gone, synthetic CA hashes are in.
        assert!(!new_aterm.contains(SELF_IA));
        assert!(!new_aterm.contains(INPUT_OUT_IA));
        assert!(new_aterm.contains(SELF_CA));
        assert!(new_aterm.contains(INPUT_OUT_CA));
        // inputDrvs cleared, the synthetic CA input source folded into inputSrcs.
        // The serialized form for an empty inputDrvs is "[]".
        assert!(new_aterm.contains(&format!(
            "/nix/store/{}-input-out",
            INPUT_OUT_CA
        )));
        assert!(!new_aterm.contains(&format!("/nix/store/{}-inp.drv", INPUT_DRV)));
    }

    #[test]
    fn ia_path_changes_when_input_synthetic_ca_changes() {
        let aterm = synthetic_ia_aterm();

        let mut subs_a: HashMap<String, String> = HashMap::new();
        subs_a.insert(
            format!("/nix/store/{}-self", SELF_IA),
            format!("/nix/store/{}-self", SELF_CA),
        );
        subs_a.insert(
            format!("/nix/store/{}-input-out", INPUT_OUT_IA),
            format!("/nix/store/{}-input-out", INPUT_OUT_CA),
        );

        let alt_input_ca = "11111111111111111111111111111111";
        let mut subs_b: HashMap<String, String> = HashMap::new();
        subs_b.insert(
            format!("/nix/store/{}-self", SELF_IA),
            format!("/nix/store/{}-self", SELF_CA),
        );
        subs_b.insert(
            format!("/nix/store/{}-input-out", INPUT_OUT_IA),
            format!("/nix/store/{}-input-out", alt_input_ca),
        );

        let input_a = vec![
            StorePath::<String>::from_absolute_path(
                format!("/nix/store/{}-input-out", INPUT_OUT_CA).as_bytes(),
            )
            .expect("valid"),
        ];
        let input_b = vec![
            StorePath::<String>::from_absolute_path(
                format!("/nix/store/{}-input-out", alt_input_ca).as_bytes(),
            )
            .expect("valid"),
        ];

        let (drv_a, _) =
            compute_resolved_input_hash_ia("self", aterm.as_bytes(), input_a, &subs_a).unwrap();
        let (drv_b, _) =
            compute_resolved_input_hash_ia("self", aterm.as_bytes(), input_b, &subs_b).unwrap();
        assert_ne!(drv_a, drv_b);
    }
}
