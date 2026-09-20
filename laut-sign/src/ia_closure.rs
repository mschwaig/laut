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
    fod_outputs: HashSet<String>,
    global_hashes: BTreeSet<String>,
    hash_to_path: HashMap<String, String>,
}

impl Walker {
    pub fn new() -> Self {
        Walker {
            memo: HashMap::new(),
            fod_outputs: HashSet::new(),
            global_hashes: BTreeSet::new(),
            hash_to_path: HashMap::new(),
        }
    }

    pub fn set_global_candidates(
        &mut self,
        hashes: BTreeSet<String>,
        map: HashMap<String, String>,
    ) {
        self.global_hashes = hashes;
        self.hash_to_path = map;
    }

    /// Register a FOD output path. FOD outputs are already content-addressed
    /// — their IA path is their synthetic CA path. The walker skips scanning
    /// them entirely.
    pub fn register_fod(&mut self, path: String) {
        self.fod_outputs.insert(path);
    }

    /// Synthetic CA hash (32-char nixbase32) of `path`'s rewritten-content
    /// equivalent. Recursively processes the path's runtime references first
    /// and memoizes by IA store path.
    pub fn synthetic_ca_hash(&mut self, path: &str) -> Result<String, Error> {
        if let Some(entry) = self.memo.get(path) {
            return Ok(nixbase32::encode(entry.synthetic_ca_path.digest()));
        }
        if self.fod_outputs.contains(path) {
            let sp = StorePath::<String>::from_absolute_path(path.as_bytes()).map_err(|e| {
                Error::Hash(format!("fod path {} parse: {:?}", path, e))
            })?;
            let hash = nixbase32::encode(sp.digest());
            self.memo
                .insert(path.to_owned(), MemoEntry { synthetic_ca_path: sp });
            return Ok(hash);
        }
        let sp = self.compute_pass1(path)?;
        let hash = nixbase32::encode(sp.digest());
        self.memo
            .insert(path.to_owned(), MemoEntry { synthetic_ca_path: sp });
        Ok(hash)
    }

    /// Synthetic CA store path of `path`. Wraps [`synthetic_ca_hash`] so the
    /// caller doesn't have to reconstruct the path from name + hash.
    pub fn synthetic_ca_path(&mut self, path: &str) -> Result<StorePath<String>, Error> {
        self.synthetic_ca_hash(path)?;
        Ok(self.memo[path].synthetic_ca_path.clone())
    }

    fn compute_pass1(&mut self, path: &str) -> Result<StorePath<String>, Error> {
        let self_ia_hash = extract_store_hash(path)?;

        let scanned = scan_for_references(Path::new(path), &self.global_hashes)?;

        let mut deps_rewrites: HashMap<String, String> = HashMap::new();
        let mut refs_as_ca: Vec<String> = Vec::new();
        for ref_hash in &scanned {
            if ref_hash == &self_ia_hash {
                continue;
            }
            let full_path = self
                .hash_to_path
                .get(ref_hash)
                .cloned()
                .unwrap_or_else(|| format!("/nix/store/{}-dummy", ref_hash));
            let ref_ca_hash = self.synthetic_ca_hash(&full_path)?;
            deps_rewrites.insert(ref_hash.clone(), ref_ca_hash);
            refs_as_ca.push(self.memo[&full_path].synthetic_ca_path.to_absolute_path());
        }

        let name = extract_store_name(path)?;
        let sp = rewrite_to_ca_pass1(
            Path::new(path),
            &name,
            &deps_rewrites,
            &self_ia_hash,
            &refs_as_ca,
        )?;
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
            let full_path = self
                .hash_to_path
                .get(ref_hash)
                .cloned()
                .unwrap_or_else(|| format!("/nix/store/{}-dummy", ref_hash));
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

impl Default for Walker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_compat::{nixhash::CAHash, store_path::build_ca_path};

    #[test]
    fn bootstrap_stdenv_path_difference_is_explained_by_source_references() {
        // Corrected-Nix small experiment: final NAR and castore agree, but the
        // signer supplies only the bootstrap output reference, omitting sources.
        // This characterizes the path discrepancy, not a source-normalization fix.
        let hash = nixbase32::decode(
            "1i0sksjsmwjiikfjy1bb14w6fbgchjgvykzmn6gwzc6khjhyac8w",
        )
        .unwrap();
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
