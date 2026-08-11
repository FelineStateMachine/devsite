//! The loopback HTTP hop, and the path validation that guards it.

use anyhow::{Context, Result};
use devsite_proto::wire::{ErrorCode, Method, Response};
use url::Url;

/// Ceiling on an upstream response body. Keeps a large local service from blowing up the
/// daemon or the frame limit.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Reject anything that could redirect the request away from the configured origin.
///
/// The peer supplies only a path. Without this check a peer could send an absolute URL
/// (`http://evil.example/`) or traverse with `..` and turn the daemon into an open proxy —
/// exactly the property the whole design exists to prevent.
pub fn validate_path(path: &str) -> Result<&str, ErrorCode> {
    if !path.starts_with('/') {
        return Err(ErrorCode::BadRequest);
    }
    // `//host/x` is a protocol-relative URL and would re-target the request when joined.
    if path.starts_with("//") {
        return Err(ErrorCode::BadRequest);
    }
    if path.contains("..") {
        return Err(ErrorCode::BadRequest);
    }
    if path.contains(['\\', '\r', '\n', '\0']) {
        return Err(ErrorCode::BadRequest);
    }
    Ok(path)
}

/// Build the upstream URL from the *configured* origin plus a validated path.
///
/// `Url::join` would happily replace the whole origin if given an absolute URL, so
/// `validate_path` must run first — it does, on the line below, and the result is used
/// rather than the raw input.
pub fn upstream_url(origin: &Url, path: &str) -> Result<Url, ErrorCode> {
    let path = validate_path(path)?;
    origin.join(path).map_err(|_| ErrorCode::BadRequest)
}

/// Perform the loopback request and turn it into a response frame.
pub async fn fetch(
    http: &reqwest::Client,
    origin: &Url,
    method: Method,
    path: &str,
) -> Response {
    let url = match upstream_url(origin, path) {
        Ok(url) => url,
        Err(code) => {
            return Response::Error {
                code,
                message: "invalid path".to_string(),
            }
        }
    };

    match perform(http, method, url).await {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!("upstream request failed: {err:#}");
            Response::Error {
                code: ErrorCode::UpstreamUnavailable,
                message: "local service did not respond".to_string(),
            }
        }
    }
}

async fn perform(http: &reqwest::Client, method: Method, url: Url) -> Result<Response> {
    let request = match method {
        Method::Get => http.get(url.clone()),
        Method::Head => http.head(url.clone()),
    };
    let response = request
        .timeout(UPSTREAM_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("requesting {url}"))?;

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    // Check the advertised length first so an oversized body is refused before it is
    // buffered, then re-check after reading since the header is only a hint.
    if response.content_length().is_some_and(|n| n as usize > MAX_BODY_BYTES) {
        return Ok(Response::Error {
            code: ErrorCode::UpstreamTooLarge,
            message: "local service response is too large".to_string(),
        });
    }

    let body = response.bytes().await.context("reading upstream body")?;
    if body.len() > MAX_BODY_BYTES {
        return Ok(Response::Error {
            code: ErrorCode::UpstreamTooLarge,
            message: "local service response is too large".to_string(),
        });
    }

    Ok(Response::Http {
        status,
        content_type,
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Url {
        Url::parse("http://127.0.0.1:4101").unwrap()
    }

    #[test]
    fn accepts_ordinary_paths() {
        assert!(upstream_url(&origin(), "/").is_ok());
        assert_eq!(
            upstream_url(&origin(), "/chat").unwrap().as_str(),
            "http://127.0.0.1:4101/chat"
        );
    }

    #[test]
    fn refuses_to_become_an_open_proxy() {
        // Each of these, if joined naively, retargets the request at another host.
        for hostile in [
            "http://evil.example/",
            "https://evil.example/",
            "//evil.example/",
            "\\\\evil.example\\",
        ] {
            let result = upstream_url(&origin(), hostile);
            assert!(result.is_err(), "{hostile} should have been rejected");
        }
    }

    #[test]
    fn refuses_traversal_and_control_characters() {
        for hostile in ["/../etc/passwd", "/a/../../b", "/x\r\nHost: evil", "/x\0"] {
            assert!(
                upstream_url(&origin(), hostile).is_err(),
                "{hostile} should have been rejected"
            );
        }
    }

    #[test]
    fn requires_an_absolute_path() {
        assert!(upstream_url(&origin(), "chat").is_err());
        assert!(upstream_url(&origin(), "").is_err());
    }
}
