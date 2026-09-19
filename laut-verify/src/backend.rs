//! How the orchestrator obtains derivation data and signatures.
//!
//! Real runs shell out via `laut_sign::nix_cmd` for nix data and dispatch
//! by URL scheme for signatures: `http(s)://` goes over HTTP via
//! `signature_verify::fetch_signatures_from_cache`, `file://` reads from
//! `<path>/traces/aterm/<input_hash>` on disk. Tests inject an in-memory backend
//! backed by pre-loaded fixtures so the orchestrator never touches the
//! system `nix` binary or the network.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    NixCmd(#[from] laut_sign::nix_cmd::Error),
    #[error("no aterm fixture for {0:?}")]
    MissingAtermFixture(String),
    #[error("{0}")]
    SignatureFetch(#[from] crate::signature_verify::Error),
    #[error("unsupported cache URL scheme in {url:?} (expected http://, https://, or file://)")]
    UnsupportedCacheUrl { url: String },
    #[error("io error reading {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Cache URL transport. `--cache` accepts either form; tests typically use
/// `file://` so they don't need a running HTTP server.
pub enum CacheTransport {
    Http(String),
    File(PathBuf),
}

/// Recognise the URL scheme and return its transport. Unknown schemes are an
/// error — silently treating them as "skip this cache" hides misconfiguration.
pub fn parse_cache_url(url: &str) -> Result<CacheTransport, Error> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(CacheTransport::Http(url.to_owned()))
    } else if let Some(rest) = url.strip_prefix("file://") {
        Ok(CacheTransport::File(PathBuf::from(rest)))
    } else {
        Err(Error::UnsupportedCacheUrl {
            url: url.to_owned(),
        })
    }
}

pub trait Backend {
    /// Return the raw JSON from `nix derivation show --recursive <drv_path>`.
    fn derivation_show_recursive(&self, drv_path: &str) -> Result<String, Error>;

    /// Return the ATerm representation of one derivation (`nix store cat <drv>`).
    fn derivation_aterm(&self, drv_path: &str) -> Result<String, Error>;

    /// Fetch the Nix resolved-input scheme's bundle collection from `cache_url`.
    /// `Ok(None)` means "not in this cache".
    fn fetch_signatures(&self, cache_url: &str, input_hash: &str)
    -> Result<Option<Vec<u8>>, Error>;
}

pub struct RealBackend;

impl Backend for RealBackend {
    fn derivation_show_recursive(&self, drv_path: &str) -> Result<String, Error> {
        Ok(laut_sign::nix_cmd::derivation_show_recursive(drv_path)?)
    }

    fn derivation_aterm(&self, drv_path: &str) -> Result<String, Error> {
        Ok(laut_sign::nix_cmd::derivation_aterm(drv_path)?)
    }

    fn fetch_signatures(
        &self,
        cache_url: &str,
        input_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        match parse_cache_url(cache_url)? {
            CacheTransport::Http(url) => {
                let base_url = match laut_sign::http_cache::parse_http_cache_url(&url) {
                    Ok(b) => b,
                    // Already passed scheme check; only a malformed http URL
                    // gets here. Treat as "not in this cache" rather than
                    // failing the whole verify.
                    Err(_) => return Ok(None),
                };
                Ok(crate::signature_verify::fetch_signatures_from_cache(
                    &base_url, input_hash,
                )?)
            }
            CacheTransport::File(dir) => {
                let path = dir.join(laut_sign::http_cache::trace_path(
                    laut_sign::attestation::NIX_RESOLVED_INPUT,
                    input_hash,
                ));
                match fs::read(&path) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(source) => Err(Error::Io {
                        path: path.display().to_string(),
                        source,
                    }),
                }
            }
        }
    }
}

/// In-memory backend used by integration tests. Pre-populated from fixture files.
pub struct InMemoryBackend {
    pub recursive_json: String,
    pub aterms: HashMap<String, String>,
    /// `input_hash -> JSON Lines bundle collection bytes`.
    pub signatures: HashMap<String, Vec<u8>>,
}

impl Backend for InMemoryBackend {
    fn derivation_show_recursive(&self, _drv_path: &str) -> Result<String, Error> {
        Ok(self.recursive_json.clone())
    }

    fn derivation_aterm(&self, drv_path: &str) -> Result<String, Error> {
        self.aterms
            .get(drv_path)
            .cloned()
            .ok_or_else(|| Error::MissingAtermFixture(drv_path.to_owned()))
    }

    fn fetch_signatures(
        &self,
        _cache_url: &str,
        input_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.signatures.get(input_hash).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laut_sign::{attestation::NIX_RESOLVED_INPUT, http_cache::trace_path};

    #[test]
    fn file_lookup_uses_the_selected_input_scheme() {
        let root = tempfile::tempdir().unwrap();
        let url = format!("file://{}", root.path().display());
        let other = root.path().join(trace_path("other-input", "hash"));
        fs::create_dir_all(other.parent().unwrap()).unwrap();
        fs::write(other, b"other scheme").unwrap();
        fs::write(root.path().join("traces/hash"), b"flat object").unwrap();
        assert!(
            RealBackend
                .fetch_signatures(&url, "hash")
                .unwrap()
                .is_none()
        );

        let selected = root.path().join(trace_path(NIX_RESOLVED_INPUT, "hash"));
        fs::create_dir_all(selected.parent().unwrap()).unwrap();
        fs::write(selected, b"selected object").unwrap();
        assert_eq!(
            RealBackend.fetch_signatures(&url, "hash").unwrap(),
            Some(b"selected object".to_vec())
        );
    }

    #[test]
    fn http_lookup_preserves_cache_prefix_and_scheme() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/cache/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for (status, body) in [("200 OK", "bundles"), ("404 Not Found", "")] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                assert_eq!(
                    request,
                    "GET /cache/traces/aterm/hash HTTP/1.1\r\n"
                );
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        assert_eq!(
            RealBackend.fetch_signatures(&url, "hash").unwrap(),
            Some(b"bundles".to_vec())
        );
        assert!(
            RealBackend
                .fetch_signatures(&url, "hash")
                .unwrap()
                .is_none()
        );
        server.join().unwrap();
    }
}
