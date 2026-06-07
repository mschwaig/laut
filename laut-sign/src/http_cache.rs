//! HTTP signature cache: parse the cache URL and upload signatures.
//!
//! `upload_signature` performs a conditional create followed by retries with
//! `If-Match`. Concurrent uploads from other builders for the same input hash
//! collide on the cache file and are detected via 412 Precondition Failed;
//! the retry loop then GETs the now-populated traces file and appends.

use serde_json::{Value, json};

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
        Ok(resp) => {
            let etag = resp
                .header("ETag")
                .map(|s| s.trim_matches('"').to_owned())
                .unwrap_or_default();
            let body = resp.into_string()?;
            let content: Value = serde_json::from_str(&body)?;
            Ok(Some((content, etag)))
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

    for _ in 0..MAX_RETRIES {
        let response = match get_existing(&url)? {
            None => {
                // No traces file yet — conditional create. If a concurrent
                // builder created it between our GET and PUT, the server
                // returns 412 and we retry through the merge path.
                let body = json!({ "signatures": [signature] }).to_string();
                ureq::request("PUT", &url)
                    .set("Content-Type", "application/json")
                    .set("If-None-Match", "*")
                    .send_string(&body)
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
                ureq::request("PUT", &url)
                    .set("Content-Type", "application/json")
                    .set("If-Match", &format!("\"{}\"", etag))
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
