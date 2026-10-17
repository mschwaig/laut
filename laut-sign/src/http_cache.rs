//! HTTP signature cache: parse the cache URL and upload signatures.
//!
//! `upload_signature` performs a conditional create followed by retries with
//! `If-Match`. Concurrent uploads from other builders for the same input hash
//! collide on the cache file and are detected via 412 Precondition Failed;
//! the retry loop then GETs the now-populated traces file and appends.

use serde_json::{Value, json};
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

/// Fetch existing `{ "signatures": [...] }` plus its ETag, or `None` on 404.
fn get_existing(url: &str) -> Result<Option<(Value, String)>, Error> {
    match ureq::get(url).call() {
        Ok(mut resp) => {
            let etag = resp
                .headers()
                .get("ETag")
                .and_then(|s| s.to_str().ok())
                .map(|s| s.trim_matches('"').to_owned())
                .unwrap_or_default();
            // Streaming reads preserve support for trace files larger than 10 MiB.
            let mut body = Vec::new();
            resp.body_mut().as_reader().read_to_end(&mut body)?;
            let body = String::from_utf8_lossy(&body);
            let content: Value = serde_json::from_str(&body)?;
            Ok(Some((content, etag)))
        }
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(e) => Err(Error::Http(format!("{}", e))),
    }
}

/// Upload `signature` to `<store_url>/traces/<input_hash>`. If another builder
/// is publishing the same input hash concurrently, ETag-based optimistic
/// concurrency merges the lists across retries.
pub fn upload_signature(store_url: &str, input_hash: &str, signature: &str) -> Result<(), Error> {
    let base_url = parse_http_cache_url(store_url)?;
    let url = format!("{}/traces/{}", base_url, input_hash);

    for _ in 0..MAX_RETRIES {
        let response = match get_existing(&url)? {
            None => {
                // No traces file yet — conditional create. If a concurrent
                // builder created it between our GET and PUT, the server
                // returns 412 and we retry through the merge path.
                let body = json!({ "signatures": [signature] }).to_string();
                ureq::put(&url)
                    .header("Content-Type", "application/json")
                    .header("If-None-Match", "*")
                    .send(&body)
            }
            Some((content, etag)) => {
                let mut signatures: Vec<Value> = content
                    .get("signatures")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if signatures.iter().any(|s| s.as_str() == Some(signature)) {
                    return Ok(());
                }
                signatures.push(Value::String(signature.to_owned()));
                let body = json!({ "signatures": signatures }).to_string();
                ureq::put(&url)
                    .header("Content-Type", "application/json")
                    .header("If-Match", &format!("\"{}\"", etag))
                    .send(&body)
            }
        };

        match response {
            Ok(_) => return Ok(()),
            Err(ureq::Error::StatusCode(412 | 409)) => continue,
            Err(e) => return Err(Error::Http(format!("{}", e))),
        }
    }
    Err(Error::MaxRetries(MAX_RETRIES))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    fn serve(responses: Vec<(u16, String, String)>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, headers, body) in responses {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "expected another HTTP request");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap();
                    }
                }
                let mut request_body = vec![0; content_length];
                reader.read_exact(&mut request_body).unwrap();
                request.push_str(std::str::from_utf8(&request_body).unwrap());
                requests.push(request);
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        (url, server)
    }

    #[test]
    fn upload_creates_conditionally() {
        let (url, server) = serve(vec![
            (404, String::new(), String::new()),
            (201, String::new(), String::new()),
        ]);
        upload_signature(&url, "hash", "new").unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /traces/hash HTTP/1.1\r\n"));
        assert!(requests[1].starts_with("PUT /traces/hash HTTP/1.1\r\n"));
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("\r\nif-none-match: *\r\n")
        );
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("\r\ncontent-type: application/json\r\n")
        );
        let body: Value =
            serde_json::from_str(requests[1].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body, json!({"signatures": ["new"]}));
    }

    #[test]
    fn upload_retries_conflicts_merges_and_deduplicates() {
        let existing = json!({"signatures": ["other"]}).to_string();
        let merged = json!({"signatures": ["other", "new"]}).to_string();
        let (url, server) = serve(vec![
            (404, String::new(), String::new()),
            (412, String::new(), String::new()),
            (200, "ETag: \"first\"\r\n".into(), existing.clone()),
            (409, String::new(), String::new()),
            (200, "ETag: \"second\"\r\n".into(), existing),
            (200, String::new(), String::new()),
            (200, "ETag: \"third\"\r\n".into(), merged.clone()),
        ]);
        upload_signature(&url, "hash", "new").unwrap();
        upload_signature(&url, "hash", "new").unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 7);
        for (i, etag) in [(3, "first"), (5, "second")] {
            assert!(
                requests[i]
                    .to_ascii_lowercase()
                    .contains(&format!("\r\nif-match: \"{etag}\"\r\n"))
            );
            assert_eq!(requests[i].split_once("\r\n\r\n").unwrap().1, merged);
        }
        assert!(requests[6].starts_with("GET "));
    }

    #[test]
    fn upload_merges_existing_body_larger_than_ten_mib() {
        let large_signature = "x".repeat(10 * 1024 * 1024 + 1);
        let existing = json!({"signatures": [large_signature]}).to_string();
        let (url, server) = serve(vec![
            (200, "ETag: \"large\"\r\n".into(), existing),
            (200, String::new(), String::new()),
        ]);
        upload_signature(&url, "hash", "new").unwrap();
        let requests = server.join().unwrap();
        let body: Value =
            serde_json::from_str(requests[1].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body, json!({"signatures": [large_signature, "new"]}));
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
