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

#[derive(Debug)]
pub enum Error {
    Parse(String),
    InvalidContentHashPath(String),
    Placeholder(String),
    Path(String),
    MissingResolution(String),
    NonUtf8Aterm,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(s) => write!(f, "failed to parse derivation ATerm: {}", s),
            Error::InvalidContentHashPath(s) => write!(f, "{}", s),
            Error::Placeholder(s) => write!(f, "failed to compute placeholder: {}", s),
            Error::Path(s) => write!(f, "failed to compute resolved drv path: {}", s),
            Error::MissingResolution(s) => write!(f, "{}", s),
            Error::NonUtf8Aterm => write!(f, "resolved ATerm bytes are not valid UTF-8"),
        }
    }
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
