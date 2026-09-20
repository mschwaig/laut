//! Closure walker for the IA→synthetic-CA recursion.
//!
//! Walks the runtime closure of one or more requested root output paths,
//! computing each closure node's synthetic Nix CA store path (via pass-1) and
//! each root's BASE64URL_NOPAD castore Entry of the rewritten content (via
//! pass-2). Results are memoized by the IA store path; the verifier walks the
//! same shape independently.
//!
//! References are discovered by scanning against the candidates supplied by
//! the caller, not by querying Nix's registered reference set. Completeness of
//! that candidate set matters independently of the rewritten NAR identity.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use laut_compat::content_hash::{
    HashError, Pass2Result, rewrite_to_ca_pass1, rewrite_to_ca_pass2, scan_for_references,
};
use nix_compat::nixbase32;
use nix_compat::nixhash::NixHash;
use nix_compat::store_path::StorePath;

use crate::drv_json::{self, DrvJson};
use crate::nix_cmd;
use crate::store_path::{self, extract_store_hash, extract_store_name};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("nix cmd: {0}")]
    NixCmd(#[from] nix_cmd::Error),
    #[error("store path: {0}")]
    StorePath(#[from] store_path::Error),
    #[error("hash error: {0}")]
    Hash(String),
}

impl From<HashError> for Error {
    fn from(e: HashError) -> Self {
        Error::Hash(e.to_string())
    }
}

/// Output of [`Walker::root_result`] for one of the requested root output
/// paths: the synthetic Nix CA store path and pass-2 artifacts (castore
/// Entry that goes into the attestation, NAR hash + size of the
/// rewritten content for the output's sibling identities).
pub struct RootResult {
    pub synthetic_ca_path: StorePath<String>,
    pub castore_entry_base64: String,
    pub nar_hash: NixHash,
    pub nar_size: u64,
}

struct MemoEntry {
    synthetic_ca_path: StorePath<String>,
}

/// Recursive walker; one instance covers the closure of all roots passed
/// through it (the memo is shared).
pub struct Walker {
    memo: HashMap<String, MemoEntry>,
    global_hashes: BTreeSet<String>,
    hash_to_path: HashMap<String, String>,
}

impl Walker {
    /// Build the reference universe once for both signing and verification.
    /// Sources without a known output producer and FODs are boundaries: keep
    /// their declared identities rather than readdressing them as floating CA.
    pub fn from_derivations<'a>(
        derivations: impl IntoIterator<Item = &'a DrvJson>,
    ) -> Result<Self, Error> {
        let mut walker = Self {
            memo: HashMap::new(),
            global_hashes: BTreeSet::new(),
            hash_to_path: HashMap::new(),
        };
        let mut ordinary_outputs = HashSet::new();
        for drv in derivations {
            let (is_fod, _) = drv_json::classify(&drv.outputs);
            let sources = drv.input_srcs.iter().map(|path| (path, true));
            let outputs = drv
                .outputs
                .values()
                .filter_map(|output| output.path.as_ref().map(|path| (path, is_fod)));
            for (path, boundary) in sources.chain(outputs) {
                let sp =
                    StorePath::<String>::from_absolute_path(path.as_bytes()).map_err(|source| {
                        store_path::Error::Parse {
                            path: path.clone(),
                            source,
                        }
                    })?;
                let hash = nixbase32::encode(sp.digest());
                walker.global_hashes.insert(hash.clone());
                walker.hash_to_path.insert(hash, path.clone());
                if boundary {
                    walker.memo.insert(
                        path.clone(),
                        MemoEntry {
                            synthetic_ca_path: sp,
                        },
                    );
                } else {
                    ordinary_outputs.insert(path.clone());
                }
            }
        }
        // An ancestor may also mention a dependency's output as an inputSrc.
        // Do not mistake that source declaration for computed output evidence.
        for path in ordinary_outputs {
            walker.memo.remove(&path);
        }
        Ok(walker)
    }

    /// Synthetic CA hash (32-char nixbase32) of `path`'s rewritten-content
    /// equivalent. Recursively processes the path's runtime references first
    /// and memoizes by IA store path.
    pub fn synthetic_ca_hash(&mut self, path: &str) -> Result<String, Error> {
        if let Some(entry) = self.memo.get(path) {
            return Ok(nixbase32::encode(entry.synthetic_ca_path.digest()));
        }
        let sp = self.compute_pass1(path, Path::new(path))?;
        let hash = nixbase32::encode(sp.digest());
        self.memo.insert(
            path.to_owned(),
            MemoEntry {
                synthetic_ca_path: sp,
            },
        );
        Ok(hash)
    }

    /// Synthetic CA store path of `path`. Wraps [`synthetic_ca_hash`] so the
    /// caller doesn't have to reconstruct the path from name + hash.
    pub fn synthetic_ca_path(&mut self, path: &str) -> Result<StorePath<String>, Error> {
        self.synthetic_ca_hash(path)?;
        Ok(self.memo[path].synthetic_ca_path.clone())
    }

    fn compute_pass1(&mut self, path: &str, contents: &Path) -> Result<StorePath<String>, Error> {
        let self_ia_hash = extract_store_hash(path)?;

        let scanned = scan_for_references(contents, &self.global_hashes)?;

        let mut deps_rewrites: HashMap<String, String> = HashMap::new();
        let mut refs_as_ca: Vec<String> = Vec::new();
        for ref_hash in &scanned {
            if ref_hash == &self_ia_hash {
                continue;
            }
            let full_path = self.hash_to_path[ref_hash].clone();
            let ref_ca_hash = self.synthetic_ca_hash(&full_path)?;
            deps_rewrites.insert(ref_hash.clone(), ref_ca_hash);
            refs_as_ca.push(self.memo[&full_path].synthetic_ca_path.to_absolute_path());
        }
        // Substitution can change ordering; Nix hashes a set of final paths.
        refs_as_ca.sort();
        refs_as_ca.dedup();

        let name = extract_store_name(path)?;
        let sp = rewrite_to_ca_pass1(contents, &name, &deps_rewrites, &self_ia_hash, &refs_as_ca)?;
        Ok(sp)
    }

    /// Compute pass-2 for a requested root output: the BASE64URL_NOPAD castore
    /// Entry of the rewritten content. Self-reference rewrite is included so
    /// the entry reflects the fully CA-equivalent form.
    pub fn root_result(&mut self, out_path: &str) -> Result<RootResult, Error> {
        let synthetic_ca_path = self.synthetic_ca_path(out_path)?;
        let self_ia_hash = extract_store_hash(out_path)?;
        let self_ca_hash = nixbase32::encode(synthetic_ca_path.digest());

        let mut rewrites: HashMap<String, String> = HashMap::new();
        rewrites.insert(self_ia_hash.clone(), self_ca_hash);

        let scanned = scan_for_references(Path::new(out_path), &self.global_hashes)?;
        for ref_hash in &scanned {
            if ref_hash == &self_ia_hash {
                continue;
            }
            let full_path = self.hash_to_path[ref_hash].clone();
            let ref_ca_hash = self.synthetic_ca_hash(&full_path)?;
            rewrites.insert(ref_hash.clone(), ref_ca_hash);
        }

        let Pass2Result {
            castore_entry_base64,
            nar_hash,
            nar_size,
        } = rewrite_to_ca_pass2(Path::new(out_path), &rewrites)?;
        Ok(RootResult {
            synthetic_ca_path,
            castore_entry_base64,
            nar_hash,
            nar_size,
        })
    }

    /// Read-only memo lookup: synthetic CA path of a path already processed,
    /// or `None` if it hasn't been visited yet. Used by `sign.rs` to look up
    /// input drvs' outputs after the closure walk has driven them in.
    pub fn lookup(&self, path: &str) -> Option<&StorePath<String>> {
        self.memo.get(path).map(|e| &e.synthetic_ca_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laut_compat::content_hash::calculate_nar_hash;
    use nix_compat::{nixhash::CAHash, store_path::build_ca_path};
    use serde_json::json;

    const ROOT: &str = "/nix/store/22222222222222222222222222222222-result";
    const SOURCE: &str = "/nix/store/11111111111111111111111111111111-script";
    const UNUSED: &str = "/nix/store/44444444444444444444444444444444-unused";
    const FOD: &str = "/nix/store/33333333333333333333333333333333-flat-input";

    #[test]
    fn discovered_sources_and_fods_keep_their_declared_identities() {
        let drvs: Vec<DrvJson> = serde_json::from_value(json!([
            {"name": "result", "inputDrvs": {
                "/nix/store/55555555555555555555555555555555-transitive.drv": {"outputs": ["out"]}
             }, "inputSrcs": [],
             "outputs": {"out": {"path": ROOT}}},
            {"name": "transitive", "inputDrvs": {}, "inputSrcs": [SOURCE, UNUSED, FOD],
             "outputs": {"out": {"path": "/nix/store/55555555555555555555555555555555-transitive"}}},
            {"name": "fixed", "inputDrvs": {}, "inputSrcs": [SOURCE],
             "outputs": {"out": {"path": FOD, "method": "flat", "hash": "declared"}}}
        ])).unwrap();
        let mut walker = Walker::from_derivations(&drvs).unwrap();
        assert_eq!(walker.global_hashes.len(), 5);
        for boundary in [SOURCE, UNUSED, FOD] {
            // These paths need not exist: sources/FODs must not be readdressed.
            assert_eq!(
                walker
                    .synthetic_ca_path(boundary)
                    .unwrap()
                    .to_absolute_path(),
                boundary
            );
        }
        assert!(walker.lookup(ROOT).is_none());
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), format!("{SOURCE} {FOD}")).unwrap();
        let actual = walker.compute_pass1(ROOT, file.path()).unwrap();
        let (hash, _) = calculate_nar_hash(file.path(), None).unwrap();
        let expected: StorePath<String> = build_ca_path(
            "result",
            &CAHash::Nar(hash.clone()),
            vec![SOURCE, FOD],
            false,
        )
        .unwrap();
        let missing: StorePath<String> = build_ca_path(
            "result",
            &CAHash::Nar(hash.clone()),
            Vec::<&str>::new(),
            false,
        )
        .unwrap();
        let extra: StorePath<String> = build_ca_path(
            "result",
            &CAHash::Nar(hash),
            vec![SOURCE, FOD, UNUSED],
            false,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_ne!(actual, missing);
        assert_ne!(actual, extra);
    }

    #[test]
    fn ordinary_outputs_are_not_precomputed_from_source_declarations() {
        let drvs: Vec<DrvJson> = serde_json::from_value(json!([
            {"name": "ancestor", "inputDrvs": {}, "inputSrcs": [ROOT],
             "outputs": {}},
            {"name": "result", "inputDrvs": {}, "inputSrcs": [SOURCE],
             "outputs": {"out": {"path": ROOT}}}
        ]))
        .unwrap();
        for drvs in [drvs.iter().collect::<Vec<_>>(), drvs.iter().rev().collect()] {
            let mut walker = Walker::from_derivations(drvs).unwrap();
            assert!(walker.lookup(ROOT).is_none());
            assert_eq!(
                walker.synthetic_ca_path(SOURCE).unwrap().to_absolute_path(),
                SOURCE
            );
        }
    }

    #[test]
    fn references_are_sorted_after_substitution_not_by_original_ia_hash() {
        let dep = "/nix/store/00000000000000000000000000000000-dep";
        let synthetic = "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-dep";
        let drvs: Vec<DrvJson> = serde_json::from_value(json!([
            {"name": "result", "inputDrvs": {}, "inputSrcs": [SOURCE],
             "outputs": {"out": {"path": ROOT}}},
            {"name": "dep", "inputDrvs": {}, "inputSrcs": [],
             "outputs": {"out": {"path": dep}}}
        ]))
        .unwrap();
        let mut walker = Walker::from_derivations(&drvs).unwrap();
        walker.memo.insert(
            dep.into(),
            MemoEntry {
                synthetic_ca_path: StorePath::from_absolute_path(synthetic.as_bytes()).unwrap(),
            },
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), format!("{dep} {SOURCE} {ROOT}")).unwrap();
        let actual = walker.compute_pass1(ROOT, file.path()).unwrap();
        let rewrites = HashMap::from([("0".repeat(32), "z".repeat(32))]);
        let expected = rewrite_to_ca_pass1(
            file.path(),
            "result",
            &rewrites,
            &"2".repeat(32),
            &[SOURCE.into(), synthetic.into()],
        )
        .unwrap();
        let original_order = rewrite_to_ca_pass1(
            file.path(),
            "result",
            &rewrites,
            &"2".repeat(32),
            &[synthetic.into(), SOURCE.into()],
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_ne!(actual, original_order);
    }

    #[test]
    fn bootstrap_stdenv_path_difference_is_explained_by_source_references() {
        // Original regression: final NAR and castore agreed, but omitting source
        // references produced the wrong path. Keep the native bootstrap oracle.
        let hash =
            nixbase32::decode("1i0sksjsmwjiikfjy1bb14w6fbgchjgvykzmn6gwzc6khjhyac8w").unwrap();
        let content = CAHash::Nar(NixHash::Sha256(hash.try_into().unwrap()));
        let name = "bootstrap-stage0-stdenv-linux";
        let bootstrap = "/nix/store/akqphqb3rn9zvv8dbnsw9rmi2899w7f0-bootstrap-tools";
        let output_only: StorePath<String> =
            build_ca_path(name, &content, vec![bootstrap], false).unwrap();
        assert_eq!(
            output_only.to_absolute_path(),
            "/nix/store/ckbi3dpd7gr7fcs48wq2fvdwy7rnqv0k-bootstrap-stage0-stdenv-linux"
        );
        let mut references: Vec<String> = [
            "5yzw0vhkyszf2d179m0qfkgxmp5wjjx4-move-docs.sh",
            "cickvswrvann041nqxb0rxilc46svw1n-prune-libtool-files.sh",
            "cmzya9irvxzlkh7lfy6i82gbp0saxqj3-multiple-outputs.sh",
            "fyaryjvghbkpfnsyw97hb3lyb37s1pd6-move-lib64.sh",
            "h9lc1dpi14z7is86ffhl3ld569138595-audit-tmpdir.sh",
            "hxv896faph0rqxjq2ycxpcrbnngc95sz-patch-shebangs.sh",
            "jjhw2phnaip4kg0qjas3x3fsaifi8y0w-no-broken-symlinks.sh",
            "kd4xwxjpjxi71jkm6ka0np72if9rm3y0-move-sbin.sh",
            "m54bmrhj6fqz8nds5zcj97w9s9bckc9v-compress-man-pages.sh",
            "pag6l61paj1dc9sv15l7bm5c17xn5kyk-move-systemd-user-units.sh",
            "pilsssjjdxvdphlg2h19p0bfx5q0jzkn-strip.sh",
            "wgrbkkaldkrlrni33ccvm3b6vbxzb656-make-symlinks-relative.sh",
            "xyff06pkhki3qy1ls77w10s0v79c9il0-reproducible-builds.sh",
            "z7k98578dfzi6l3hsvbivzm7hfqlk0zc-set-source-date-epoch-to-latest.sh",
        ]
        .iter()
        .map(|p| format!("/nix/store/{p}"))
        .collect();
        references.push(bootstrap.into());
        references.sort();
        let native: StorePath<String> = build_ca_path(
            name,
            &content,
            references.iter().map(String::as_str).collect::<Vec<_>>(),
            false,
        )
        .unwrap();
        assert_eq!(
            native.to_absolute_path(),
            "/nix/store/yfkmixcmvq3lnijhjn3sfdbyiwz6dsp1-bootstrap-stage0-stdenv-linux"
        );
    }
}
