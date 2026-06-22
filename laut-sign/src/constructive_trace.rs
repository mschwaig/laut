//! Compute the resolved-input-hash drv path for an unresolved derivation, given a
//! resolution map for each of its input derivations' outputs.
//!
//! We parse with snix's non-validating parser, edit the `Derivation` struct
//! (drop `inputDrvs`, fold the resolved content-hash paths into `inputSrcs`),
//! serialize back to ATerm, replace upstream placeholders throughout the bytes,
//! and hand the result to [`calculate_derivation_path_from_aterm`] for the
//! final hash.

use std::collections::HashMap;

use nix_compat::derivation::{calculate_derivation_path_from_aterm, CAFloatingAlgo, Derivation};
use nix_compat::nixhash::HashAlgo;
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
/// ATerm and transform it into the structural equivalent of an unresolved
/// floating-CA derivation, so that the resulting drv path matches what a
/// natively-CA analogue would produce.
///
/// Concretely:
///   - Each output's `path` is cleared and `ca_floating` is set to
///     `r:sha256` (recursive SHA256), matching the NAR-mode CA that
///     [`rewrite_to_ca_pass1`] derives.
///   - `inputDrvs` is cleared; dep synthetic-CA paths are folded into
///     `inputSrcs`.
///   - After serialization, byte-level substitution replaces:
///       * dep output IA paths → their synthetic CA paths (from `substitutions`)
///       * own output IA paths → downstream placeholders (`hash_placeholder`)
///     The caller must put own-output placeholder mappings into
///     `substitutions` keyed by the IA path.
pub fn compute_resolved_input_hash_ia(
    drv_name: &str,
    drv_aterm: &[u8],
    input_drv_outputs_synthetic_ca: Vec<StorePath<String>>,
    substitutions: &HashMap<String, String>,
) -> Result<(String, String), Error> {
    let mut drv = Derivation::from_aterm_bytes_unchecked(drv_aterm)
        .map_err(|e| Error::Parse(format!("{:?}", e)))?;

    // Convert each output to a floating-CA shape: clear the concrete IA path
    // and declare `r:sha256` so the serialized ATerm tuple becomes
    // `("out","","r:sha256","")` — identical to a natively floating CA drv.
    for output in drv.outputs.values_mut() {
        output.path = None;
        output.ca_hash = None;
        output.ca_floating = Some(CAFloatingAlgo {
            algo: HashAlgo::Sha256,
            recursive: true,
        });
    }

    drv.input_derivations.clear();
    for sp in input_drv_outputs_synthetic_ca {
        drv.input_sources.insert(sp);
    }

    let mut aterm = drv.to_aterm_bytes();
    for (ia_path, replacement) in substitutions {
        aterm = replace_bytes(&aterm, ia_path.as_bytes(), replacement.as_bytes());
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

    use nix_compat::store_path::hash_placeholder;

    // 32-char nixbase32-valid (alphabet excludes e, o, t, u).
    const SELF_IA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    fn ia_converts_to_floating_ca_with_placeholders() {
        let aterm = synthetic_ia_aterm();

        let self_placeholder = hash_placeholder("out");
        let mut subs: HashMap<String, String> = HashMap::new();
        // Own output → downstream placeholder (as CA nix does).
        subs.insert(format!("/nix/store/{}-self", SELF_IA), self_placeholder.clone());
        // Dep output → synthetic CA path.
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
        // IA hashes are gone.
        assert!(!new_aterm.contains(SELF_IA));
        assert!(!new_aterm.contains(INPUT_OUT_IA));
        // Own output path replaced by downstream placeholder.
        assert!(new_aterm.contains(&self_placeholder));
        // Dep output replaced by synthetic CA path.
        assert!(new_aterm.contains(INPUT_OUT_CA));
        // Output tuple has floating-CA shape: empty path, r:sha256.
        assert!(new_aterm.contains(r#"("out","","r:sha256","")"#));
        // inputDrvs cleared, synthetic CA folded into inputSrcs.
        assert!(!new_aterm.contains(&format!("/nix/store/{}-inp.drv", INPUT_DRV)));
    }

    #[test]
    fn ia_path_changes_when_input_synthetic_ca_changes() {
        let aterm = synthetic_ia_aterm();
        let self_placeholder = hash_placeholder("out");

        let mut subs_a: HashMap<String, String> = HashMap::new();
        subs_a.insert(format!("/nix/store/{}-self", SELF_IA), self_placeholder.clone());
        subs_a.insert(
            format!("/nix/store/{}-input-out", INPUT_OUT_IA),
            format!("/nix/store/{}-input-out", INPUT_OUT_CA),
        );

        let alt_input_ca = "11111111111111111111111111111111";
        let mut subs_b: HashMap<String, String> = HashMap::new();
        subs_b.insert(format!("/nix/store/{}-self", SELF_IA), self_placeholder.clone());
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

    #[test]
    fn ia_path_stable_when_only_self_changes() {
        // The downstream placeholder is derived from the output name, not the
        // IA hash. So two IA drvs with different IA hashes but the same name
        // and same dep resolutions should produce the same ct_input_hash.
        let self_ia_alt = "22222222222222222222222222222222";
        let aterm_a = synthetic_ia_aterm();
        let aterm_b = synthetic_ia_aterm().replace(SELF_IA, self_ia_alt);

        let self_placeholder = hash_placeholder("out");
        let mut subs_a: HashMap<String, String> = HashMap::new();
        subs_a.insert(format!("/nix/store/{}-self", SELF_IA), self_placeholder.clone());
        subs_a.insert(
            format!("/nix/store/{}-input-out", INPUT_OUT_IA),
            format!("/nix/store/{}-input-out", INPUT_OUT_CA),
        );

        let mut subs_b: HashMap<String, String> = HashMap::new();
        subs_b.insert(format!("/nix/store/{}-self", self_ia_alt), self_placeholder.clone());
        subs_b.insert(
            format!("/nix/store/{}-input-out", INPUT_OUT_IA),
            format!("/nix/store/{}-input-out", INPUT_OUT_CA),
        );

        let input_sources = vec![
            StorePath::<String>::from_absolute_path(
                format!("/nix/store/{}-input-out", INPUT_OUT_CA).as_bytes(),
            )
            .expect("valid"),
        ];

        let (drv_a, _) =
            compute_resolved_input_hash_ia("self", aterm_a.as_bytes(), input_sources.clone(), &subs_a).unwrap();
        let (drv_b, _) =
            compute_resolved_input_hash_ia("self", aterm_b.as_bytes(), input_sources, &subs_b).unwrap();
        assert_eq!(drv_a, drv_b);
    }
}
