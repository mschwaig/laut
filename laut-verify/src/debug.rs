//! Hash-divergence debug probe.
//!
//! When `collect_resolutions` computes a `ct_input_hash` and finds no signed
//! claims for it, the most useful question is "is there a signer-side
//! preimage with a looser notion of identity, and how does it differ from
//! ours?". The probe surface lets the orchestrator emit that event and
//! plug in different lookup + diff strategies without bloating its own code.
//!
//! The default probe is a no-op; production builds never run this path.
//! The active probe writes both preimages to a temp dir and shells out to
//! `difft` for a structural diff. A bytewise check around `difft` catches
//! the case where the structural diff is empty but the bytes do differ.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A looser identity than `ct_input_hash`. Used to find signer-side preimages
/// when the exact-hash lookup misses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Identity {
    /// `payload.in.debug.drv_name` on the signer side, `udrv.name` locally.
    DrvName,
}

/// What the orchestrator knows about a step that couldn't be verified.
/// Field references are borrowed so we don't pay for `String`s on the
/// happy (no-probe) path.
pub struct LocalWitness<'a> {
    pub udrv_drv_path: &'a str,
    pub udrv_name: &'a str,
    pub udrv_input_hash: &'a str,
    pub ct_input_hash: &'a str,
    pub aterm_bytes: &'a str,
}

/// One signer-side candidate preimage retrieved from an index.
#[derive(Debug, Clone)]
pub struct PreimageCandidate {
    /// Signer's resolved drv path; basename is used as a filename for diffing.
    pub drv_path: String,
    pub aterm_preimage: String,
}

pub trait DebugProbe {
    fn on_signature_miss(&self, local: &LocalWitness<'_>);
}

/// Default. Drops events. Compile-time identical to "no probe wired".
pub struct NullProbe;
impl DebugProbe for NullProbe {
    fn on_signature_miss(&self, _local: &LocalWitness<'_>) {}
}

/// In-memory index keyed by `drv_name`. Populated permissively from a
/// listable HTTP cache (`build_from_cache_listing`). Signatures are not
/// verified before extraction; entries are tagged as such by the caller of
/// the index if it cares.
#[derive(Debug, Default)]
pub struct InMemoryCorpusIndex {
    by_drv_name: HashMap<String, Vec<PreimageCandidate>>,
}

impl InMemoryCorpusIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, drv_name: String, candidate: PreimageCandidate) {
        self.by_drv_name.entry(drv_name).or_default().push(candidate);
    }

    pub fn lookup(&self, identity: Identity, value: &str) -> &[PreimageCandidate] {
        match identity {
            Identity::DrvName => self
                .by_drv_name
                .get(value)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_drv_name.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error(
        "cache at {url:?} does not support listing /traces/ (HTTP {status}); --debug-preimage-corpus needs a cache with a listing endpoint, like the test cache server"
    )]
    ListingNotSupported { url: String, status: u16 },
    #[error("cache at {url:?} returned a listing that is not a JSON array of objects: {detail}")]
    MalformedListing { url: String, detail: String },
    #[error("failed to talk to cache at {url:?}: {source}")]
    Transport {
        url: String,
        #[source]
        source: ureq::Error,
    },
    #[error("failed to read response body from {url:?}: {source}")]
    Io {
        url: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Backend(#[from] crate::backend::Error),
    #[error("failed to read directory {path:?}: {source}")]
    DirRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read trace file {path:?}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Build an `InMemoryCorpusIndex` by listing the cache's `/traces/` directory
/// and pulling the debug block out of each JWS we find. Permissive: entries
/// whose signatures don't verify (or have no debug block at all) are simply
/// not indexed. The flag-gated invariant is "preimages are only ever
/// generated when the signer opts in", so absence is expected.
///
/// Dispatches on the same URL schemes as `Backend::fetch_signatures`:
/// `http(s)://` requires a JSON listing endpoint at `/traces/`; `file://`
/// reads `<path>/traces/` from disk.
pub fn build_corpus_from_cache(cache_url: &str) -> Result<InMemoryCorpusIndex, CorpusError> {
    match crate::backend::parse_cache_url(cache_url)? {
        crate::backend::CacheTransport::Http(url) => build_from_http(&url),
        crate::backend::CacheTransport::File(dir) => {
            build_from_dir(&dir.join("traces"))
        }
    }
}

fn build_from_http(cache_url: &str) -> Result<InMemoryCorpusIndex, CorpusError> {
    let base_url = cache_url.trim_end_matches('/');
    let listing_url = format!("{}/traces/", base_url);
    let names = fetch_listing(&listing_url)?;
    let mut index = InMemoryCorpusIndex::new();
    for name in names {
        let trace_url = format!("{}/traces/{}", base_url, name);
        let Ok(body) = fetch_bytes(&trace_url) else {
            continue;
        };
        extract_into(&mut index, &body);
    }
    Ok(index)
}

fn build_from_dir(traces_dir: &std::path::Path) -> Result<InMemoryCorpusIndex, CorpusError> {
    let mut index = InMemoryCorpusIndex::new();
    let entries = std::fs::read_dir(traces_dir).map_err(|source| CorpusError::DirRead {
        path: traces_dir.display().to_string(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| CorpusError::DirRead {
            path: traces_dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let body = std::fs::read(&path).map_err(|source| CorpusError::FileRead {
            path: path.display().to_string(),
            source,
        })?;
        extract_into(&mut index, &body);
    }
    Ok(index)
}

fn extract_into(index: &mut InMemoryCorpusIndex, body: &[u8]) {
    let Ok(parsed): serde_json::Result<Value> = serde_json::from_slice(body) else {
        return;
    };
    let Some(sigs) = parsed.get("signatures").and_then(|v| v.as_array()) else {
        return;
    };
    for sig in sigs {
        let Some(jws) = sig.as_str() else { continue };
        let Some((drv_name, drv_path, aterm)) = extract_debug_from_jws(jws) else {
            continue;
        };
        index.add(
            drv_name,
            PreimageCandidate {
                drv_path,
                aterm_preimage: aterm,
            },
        );
    }
}

fn fetch_listing(url: &str) -> Result<Vec<String>, CorpusError> {
    match ureq::get(url).call() {
        Ok(resp) => {
            let body = read_body(url, resp)?;
            let parsed: Value = serde_json::from_slice(&body).map_err(|e| {
                CorpusError::MalformedListing {
                    url: url.to_owned(),
                    detail: format!("not valid JSON: {}", e),
                }
            })?;
            // nginx ngx_http_autoindex_module / Caddy file_server format=json
            // shape: `[{"name": "...", ...}, ...]`. We only need the `name`
            // field; other metadata (type, size, mtime) is ignored.
            let arr = parsed
                .as_array()
                .ok_or_else(|| CorpusError::MalformedListing {
                    url: url.to_owned(),
                    detail: "expected a top-level JSON array".to_owned(),
                })?;
            let mut names = Vec::with_capacity(arr.len());
            for entry in arr {
                let name = entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CorpusError::MalformedListing {
                        url: url.to_owned(),
                        detail: "each array entry must be an object with a string `name` field"
                            .to_owned(),
                    })?;
                names.push(name.to_owned());
            }
            Ok(names)
        }
        Err(ureq::Error::Status(status @ (403 | 404 | 405), _)) => {
            Err(CorpusError::ListingNotSupported {
                url: url.to_owned(),
                status,
            })
        }
        Err(e) => Err(CorpusError::Transport {
            url: url.to_owned(),
            source: e,
        }),
    }
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, CorpusError> {
    let resp = ureq::get(url).call().map_err(|e| CorpusError::Transport {
        url: url.to_owned(),
        source: e,
    })?;
    read_body(url, resp)
}

fn read_body(url: &str, resp: ureq::Response) -> Result<Vec<u8>, CorpusError> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| CorpusError::Io {
            url: url.to_owned(),
            source: e,
        })?;
    Ok(buf)
}

/// Scan a JWS compact serialization for the debug block we're after, without
/// verifying the signature. Returns `(drv_name, drv_path, aterm_preimage)`
/// if all three are present.
pub fn extract_debug_from_jws(jws: &str) -> Option<(String, String, String)> {
    let mut parts = jws.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    let debug = payload.get("in").and_then(|v| v.get("debug"))?;
    let drv_name = debug.get("drv_name")?.as_str()?.to_owned();
    let drv_path = debug.get("rdrv_path")?.as_str()?.to_owned();
    let aterm = debug.get("rdrv_aterm_ca_preimage")?.as_str()?.to_owned();
    Some((drv_name, drv_path, aterm))
}

/// The active probe. Renders one bytewise + structural diff per candidate
/// the index returns, writing both preimages to `out_dir` so the operator
/// can re-run `difft` themselves.
pub struct DifftProbe {
    index: InMemoryCorpusIndex,
    out_dir: PathBuf,
}

impl DifftProbe {
    pub fn new(index: InMemoryCorpusIndex, out_dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&out_dir)?;
        Ok(Self { index, out_dir })
    }
}

impl DebugProbe for DifftProbe {
    fn on_signature_miss(&self, local: &LocalWitness<'_>) {
        let candidates = self.index.lookup(Identity::DrvName, local.udrv_name);
        if candidates.is_empty() {
            eprintln!(
                "[laut debug] no signed preimage candidates for drv_name {:?} (local ct_input_hash {})",
                local.udrv_name, local.ct_input_hash
            );
            return;
        }

        let udrv_dir = self.out_dir.join(Path::new(local.udrv_drv_path).file_name().unwrap_or_default());
        if let Err(e) = fs::create_dir_all(&udrv_dir) {
            eprintln!("[laut debug] failed to create debug dir {:?}: {}", udrv_dir, e);
            return;
        }

        let local_file = udrv_dir.join(local.ct_input_hash);
        if let Err(e) = fs::write(&local_file, local.aterm_bytes.as_bytes()) {
            eprintln!("[laut debug] failed to write local preimage: {}", e);
            return;
        }

        eprintln!(
            "[laut debug] {} candidate(s) for drv_name {:?} (local ct_input_hash {}); artifacts in {}",
            candidates.len(),
            local.udrv_name,
            local.ct_input_hash,
            udrv_dir.display()
        );

        for candidate in candidates {
            let cand_basename = Path::new(&candidate.drv_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("candidate");
            let cand_file = udrv_dir.join(cand_basename);
            if let Err(e) = fs::write(&cand_file, candidate.aterm_preimage.as_bytes()) {
                eprintln!("[laut debug] failed to write candidate preimage: {}", e);
                continue;
            }

            let bytewise_equal = candidate.aterm_preimage.as_bytes() == local.aterm_bytes.as_bytes();
            if bytewise_equal {
                eprintln!(
                    "[laut debug]   {} — bytewise identical to local preimage (divergence is elsewhere)",
                    cand_basename
                );
                continue;
            }
            eprintln!(
                "[laut debug]   {} — differs bytewise; running difft",
                cand_basename
            );

            let output = Command::new("difft")
                .arg("--color")
                .arg("always")
                .arg("--override=*:Python")
                .arg(&local_file)
                .arg(&cand_file)
                .output();
            match output {
                Ok(out) => {
                    if !out.stdout.is_empty() {
                        // difft writes the diff to stdout; we forward to stderr
                        // so it interleaves with the orchestrator's own log lines.
                        let _ = std::io::Write::write_all(&mut std::io::stderr(), &out.stdout);
                    } else {
                        eprintln!(
                            "[laut debug]   WARNING: difft reported no structural differences but the files differ bytewise — check whitespace / non-printable bytes"
                        );
                    }
                }
                Err(e) => {
                    eprintln!("[laut debug]   failed to invoke difft: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_probe_does_nothing() {
        let probe = NullProbe;
        let w = LocalWitness {
            udrv_drv_path: "/nix/store/x.drv",
            udrv_name: "x",
            udrv_input_hash: "h",
            ct_input_hash: "ct",
            aterm_bytes: "Derive(...)",
        };
        probe.on_signature_miss(&w);
    }

    #[test]
    fn index_returns_empty_for_unknown_name() {
        let idx = InMemoryCorpusIndex::new();
        assert!(idx.lookup(Identity::DrvName, "missing").is_empty());
    }

    #[test]
    fn index_returns_candidates_for_known_name() {
        let mut idx = InMemoryCorpusIndex::new();
        idx.add(
            "hello".into(),
            PreimageCandidate {
                drv_path: "/nix/store/abc-hello.drv".into(),
                aterm_preimage: "Derive(...)".into(),
            },
        );
        let candidates = idx.lookup(Identity::DrvName, "hello");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].drv_path, "/nix/store/abc-hello.drv");
    }

    #[test]
    fn extract_debug_from_well_formed_jws() {
        // Hand-build a JWS-shaped string with the debug block we expect.
        let payload = serde_json::json!({
            "in": {
                "rdrv_aterm_ca": "ct123",
                "debug": {
                    "drv_name": "hello",
                    "rdrv_path": "/nix/store/abc-hello.drv",
                    "rdrv_aterm_ca_preimage": "Derive(...)",
                }
            }
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let jws = format!("header.{}.sig", payload_b64);
        let (name, path, aterm) = extract_debug_from_jws(&jws).unwrap();
        assert_eq!(name, "hello");
        assert_eq!(path, "/nix/store/abc-hello.drv");
        assert_eq!(aterm, "Derive(...)");
    }

    #[test]
    fn extract_debug_returns_none_when_block_missing() {
        let payload = serde_json::json!({"in": {"rdrv_aterm_ca": "ct123"}});
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let jws = format!("header.{}.sig", payload_b64);
        assert!(extract_debug_from_jws(&jws).is_none());
    }
}
