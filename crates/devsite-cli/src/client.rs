//! Thin HTTP client for the control plane, used by the CLI and the daemon's heartbeat.

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct ControlPlane {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl ControlPlane {
    pub fn new(base: &str, token: Option<String>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            http: reqwest::Client::new(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let builder = self.http.request(method, format!("{}{path}", self.base));
        match &self.token {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .request(reqwest::Method::GET, path)
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        decode(response, path).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let response = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        decode(response, path).await
    }

    pub async fn put<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let response = self
            .request(reqwest::Method::PUT, path)
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {path}"))?;
        decode(response, path).await
    }

    /// POST where a 2xx with no body is the expected success.
    pub async fn post_empty<B: Serialize>(&self, path: &str, body: &B) -> Result<()> {
        let response = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        if !response.status().is_success() {
            bail!("{path} failed: {}", error_text(response).await);
        }
        Ok(())
    }
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response, path: &str) -> Result<T> {
    if !response.status().is_success() {
        bail!("{path} failed: {}", error_text(response).await);
    }
    response
        .json()
        .await
        .with_context(|| format!("parsing the response to {path}"))
}

/// Surface the server's `error` field when there is one, so the CLI shows a real message
/// rather than a bare status code.
async fn error_text(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<serde_json::Value>().await {
        Ok(value) => value
            .get("error")
            .and_then(|e| e.as_str())
            .map(|e| format!("{status}: {e}"))
            .unwrap_or_else(|| format!("{status}")),
        Err(_) => format!("{status}"),
    }
}
