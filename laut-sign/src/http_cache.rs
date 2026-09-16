//! HTTP signature cache: parse the cache URL and upload signatures.
//!
//! `upload_signature` performs a conditional create followed by retries with
//! `If-Match`. Concurrent uploads from other builders for the same input hash
//! collide on the cache file and are detected via 412 Precondition Failed;
//! the retry loop then GETs the now-populated traces file and appends.

use crate::attestation::{self, parse_json};
use std::io::Read;

const MAX_RETRIES: u32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported url scheme {0:?} (expected http or https)")]
    UnsupportedScheme(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("attestation: {0}")]
    Attestation(#[from] attestation::Error),
    #[error("cache response is missing a strong ETag")]
    MissingEtag,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("exceeded {0} retries while uploading signature")]
    MaxRetries(u32),
}

/// Validate an HTTP(S) URL and return the canonical base used for
/// `/traces/...` requests: `scheme://host[:port][/path]`, with any trailing
/// slash on the path stripped.
pub fn parse_http_cache_url(store_url: &str) -> Result<String, Error> {
    let (scheme, after_scheme) = if let Some(rest) = store_url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = store_url.strip_prefix("http://") {
        ("http", rest)
    } else {
        let bad = store_url.split("://").next().unwrap_or("");
        return Err(Error::UnsupportedScheme(bad.to_owned()));
    };
    let (netloc, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };
    if netloc.is_empty() {
        return Err(Error::InvalidUrl(store_url.to_owned()));
    }
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        Ok(format!("{}://{}", scheme, netloc))
    } else {
        Ok(format!("{}://{}{}", scheme, netloc, path))
    }
}

/// Fetch the JSON Lines collection and its exact strong ETag, or None on 404.
fn get_existing(url: &str) -> Result<Option<(String, String)>, Error> {
    match ureq::get(url).call() {
        Ok(resp) => {
            let etag = resp
                .header("ETag")
                .filter(|s| s.starts_with('"') && s.ends_with('"'))
                .ok_or(Error::MissingEtag)?
                .to_owned();
            let mut body = String::new();
            resp.into_reader()
                .take(attestation::MAX_OBJECT_BYTES + 1)
                .read_to_string(&mut body)?;
            if body.len() as u64 > attestation::MAX_OBJECT_BYTES {
                return Err(Error::Http("cache object too large".into()));
            }
            Ok(Some((body, etag)))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(Error::Http(format!("{}", e))),
    }
}

/// Upload `signature` to `<store_url>/traces/<input_hash>`. If another builder
/// is publishing the same input hash concurrently, ETag-based optimistic
/// concurrency merges the lists across retries.
pub fn upload_signature(store_url: &str, input_hash: &str, signature: &str) -> Result<(), Error> {
    let base_url = parse_http_cache_url(store_url)?;
    let url = format!("{}/traces/{}", base_url, input_hash);

    let incoming = parse_json(signature.as_bytes())?;
    attestation::parse_bundle(signature.as_bytes())?;
    let line = serde_json::to_string(&incoming)?;
    for _ in 0..MAX_RETRIES {
        let response = match get_existing(&url)? {
            None => {
                // No traces file yet — conditional create. If a concurrent
                // builder created it between our GET and PUT, the server
                // returns 412 and we retry through the merge path.
                let body = format!("{line}\n");
                ureq::request("PUT", &url)
                    .set("Content-Type", "application/x-ndjson")
                    .set("If-None-Match", "*")
                    .send_string(&body)
            }
            Some((mut body, etag)) => {
                for existing in body.lines().filter(|s| !s.trim().is_empty()) {
                    if parse_json(existing.as_bytes())? == incoming {
                        return Ok(());
                    }
                }
                if !body.is_empty() && !body.ends_with('\n') {
                    body.push('\n');
                }
                body.push_str(&line);
                body.push('\n');
                if body.len() as u64 > attestation::MAX_OBJECT_BYTES {
                    return Err(Error::Http("cache object too large".into()));
                }
                ureq::request("PUT", &url)
                    .set("Content-Type", "application/x-ndjson")
                    .set("If-Match", &etag)
                    .send_string(&body)
            }
        };

        match response {
            Ok(_) => return Ok(()),
            Err(ureq::Error::Status(412, _)) | Err(ureq::Error::Status(409, _)) => continue,
            Err(e) => return Err(Error::Http(format!("{}", e))),
        }
    }
    Err(Error::MaxRetries(MAX_RETRIES))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_conflict_merges_without_losing_other_publishers() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let bundle = attestation::create_trace_bundle(&"0".repeat(32), None,
            &serde_json::json!({"out": {"path": format!("/nix/store/{}-test", "0".repeat(32)), "hash": format!("sha256:{}", "0".repeat(52))}}),
            &serde_json::json!({"out": "CgA"}), 42, None, None, &key, false).unwrap();
        let serialized = serde_json::to_string(&bundle).unwrap();
        let expected = serialized.clone();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, headers, body) in [
                ("404 Not Found", "", String::new()),
                ("412 Precondition Failed", "", String::new()),
                (
                    "200 OK",
                    "ETag: \"other\"\r\n",
                    "{\"preserve\":true}\n".into(),
                ),
                ("200 OK", "", String::new()),
                (
                    "200 OK",
                    "ETag: \"merged\"\r\n",
                    format!("{{\"preserve\":true}}\n{expected}\n"),
                ),
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut header = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = n.trim().parse().unwrap();
                    }
                    header.push_str(&line);
                }
                let mut received = vec![0; length];
                reader.read_exact(&mut received).unwrap();
                requests.push((header, String::from_utf8(received).unwrap()));
                write!(socket, "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        upload_signature(&url, &"0".repeat(32), &serialized).unwrap();
        // A retry of the exact published bundle performs only the final GET.
        upload_signature(&url, &"0".repeat(32), &serialized).unwrap();
        let requests = server.join().unwrap();
        assert!(requests[1].0.to_lowercase().contains("if-none-match: *"));
        assert!(requests[3].0.to_lowercase().contains("if-match: \"other\""));
        assert!(requests[3].1.starts_with("{\"preserve\":true}\n"));
        assert_eq!(
            parse_json(requests[3].1.lines().nth(1).unwrap().as_bytes()).unwrap(),
            parse_json(serialized.as_bytes()).unwrap()
        );
    }

    #[test]
    fn strips_trailing_slash() {
        assert_eq!(
            parse_http_cache_url("http://cache:9000/").unwrap(),
            "http://cache:9000"
        );
        assert_eq!(
            parse_http_cache_url("http://cache:9000").unwrap(),
            "http://cache:9000"
        );
    }

    #[test]
    fn preserves_path_no_trailing_slash() {
        assert_eq!(
            parse_http_cache_url("https://example.com/cache/").unwrap(),
            "https://example.com/cache"
        );
        assert_eq!(
            parse_http_cache_url("https://example.com/cache").unwrap(),
            "https://example.com/cache"
        );
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = parse_http_cache_url("s3://bucket").unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme(s) if s == "s3"));
    }

    #[test]
    fn rejects_missing_host() {
        let err = parse_http_cache_url("http:///path").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }
}
