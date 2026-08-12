//! OIDC authorization-code + PKCE login adapter.
//!
//! Shoo is the zero-configuration default, not an application dependency. Another public
//! OIDC client can be selected entirely with `DEVSITE_OIDC_*` settings. This module ends
//! at `ExternalIdentity`; account and session policy remain in the application port.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::api::{self, Shared};
use crate::auth::{self, ExternalIdentity};

const SHOO_ISSUER: &str = "https://shoo.dev";
const LOGIN_ATTEMPT_TTL_SECS: u64 = 10 * 60;
const MAX_PENDING_LOGINS: usize = 4096;
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);

pub struct OidcConfig {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
    client_id: String,
    scopes: String,
    algorithms: Vec<Algorithm>,
    callback_uri: String,
}

impl OidcConfig {
    pub fn from_env(public_origin: &str) -> Result<Self> {
        let issuer = env_or("DEVSITE_OIDC_ISSUER", SHOO_ISSUER);
        let authorization_endpoint = endpoint_from_env(
            "DEVSITE_OIDC_AUTHORIZATION_ENDPOINT",
            &format!("{}/authorize", issuer.trim_end_matches('/')),
        )?;
        let token_endpoint = endpoint_from_env(
            "DEVSITE_OIDC_TOKEN_ENDPOINT",
            &format!("{}/token", issuer.trim_end_matches('/')),
        )?;
        let jwks_uri = endpoint_from_env(
            "DEVSITE_OIDC_JWKS_URI",
            &format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')),
        )?;
        let client_id = std::env::var("DEVSITE_OIDC_CLIENT_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("origin:{public_origin}"));
        let scopes = env_or("DEVSITE_OIDC_SCOPES", "openid");
        if !scopes.split_whitespace().any(|scope| scope == "openid") {
            bail!("DEVSITE_OIDC_SCOPES must include openid");
        }
        // Keep Shoo's existing ES256 pin as the safe default. A different provider must
        // explicitly name its asymmetric signing algorithm.
        let algorithms = parse_algorithms(&env_or("DEVSITE_OIDC_ALGORITHMS", "ES256"))?;

        let issuer_url = Url::parse(&issuer).context("DEVSITE_OIDC_ISSUER is not a URL")?;
        validate_provider_url("DEVSITE_OIDC_ISSUER", &issuer_url)?;

        Ok(Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            client_id,
            scopes,
            algorithms,
            callback_uri: format!("{}/auth/callback", public_origin.trim_end_matches('/')),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn endpoint_from_env(name: &str, default: &str) -> Result<Url> {
    let value = env_or(name, default);
    let url = Url::parse(&value).with_context(|| format!("{name} is not a URL"))?;
    validate_provider_url(name, &url)?;
    Ok(url)
}

fn validate_provider_url(name: &str, url: &Url) -> Result<()> {
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("{name} must use HTTPS (HTTP is allowed only for loopback development)");
    }
    Ok(())
}

fn parse_algorithms(value: &str) -> Result<Vec<Algorithm>> {
    let mut algorithms = Vec::new();
    for name in value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let algorithm = Algorithm::from_str(name)
            .with_context(|| format!("unsupported OIDC signing algorithm {name}"))?;
        if matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            bail!("symmetric OIDC signing algorithm {name} is not accepted");
        }
        if !algorithms.contains(&algorithm) {
            algorithms.push(algorithm);
        }
    }
    if algorithms.is_empty() {
        bail!("DEVSITE_OIDC_ALGORITHMS must name at least one asymmetric algorithm");
    }
    Ok(algorithms)
}

struct PendingLogin {
    verifier: String,
    return_to: String,
    expires_at: u64,
}

struct OidcAdapter {
    config: OidcConfig,
    http: reqwest::Client,
    keys: RwLock<Option<(JwkSet, Instant)>>,
}

impl OidcAdapter {
    fn new(config: OidcConfig) -> Result<Self> {
        Ok(Self {
            config,
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .build()
                .context("building OIDC HTTP client")?,
            keys: RwLock::new(None),
        })
    }

    fn authorization_url(&self, state: &str, challenge: &str) -> Url {
        let mut url = self.config.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.callback_uri)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        url
    }

    async fn authenticate(&self, code: &str, verifier: &str) -> Result<ExternalIdentity> {
        let form = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", code)
                .append_pair("redirect_uri", &self.config.callback_uri)
                .append_pair("client_id", &self.config.client_id)
                .append_pair("code_verifier", verifier);
            serializer.finish()
        };

        let response = self
            .http
            .post(self.config.token_endpoint.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .context("exchanging the OIDC authorization code")?
            .error_for_status()
            .context("the OIDC token endpoint rejected the authorization code")?
            .json::<TokenResponse>()
            .await
            .context("parsing the OIDC token response")?;

        self.verify(&response.id_token).await
    }

    async fn keys(&self) -> Result<JwkSet> {
        if let Some((keys, fetched)) = self.keys.read().unwrap().as_ref() {
            if fetched.elapsed() < JWKS_TTL {
                return Ok(keys.clone());
            }
        }

        let keys = self
            .http
            .get(self.config.jwks_uri.clone())
            .send()
            .await
            .context("fetching OIDC JWKS")?
            .error_for_status()
            .context("OIDC JWKS endpoint returned an error status")?
            .json::<JwkSet>()
            .await
            .context("parsing OIDC JWKS")?;
        *self.keys.write().unwrap() = Some((keys.clone(), Instant::now()));
        Ok(keys)
    }

    async fn verify(&self, id_token: &str) -> Result<ExternalIdentity> {
        let token_header =
            jsonwebtoken::decode_header(id_token).context("unreadable token header")?;
        if !self.config.algorithms.contains(&token_header.alg) {
            bail!("unexpected token algorithm {:?}", token_header.alg);
        }
        let kid = token_header.kid.context("token has no key id")?;
        let keys = self.keys().await?;
        let jwk = keys
            .find(&kid)
            .with_context(|| format!("no OIDC key matches kid {kid}"))?;
        validate_jwk(jwk, token_header.alg)?;
        let key = DecodingKey::from_jwk(jwk).context("OIDC key is not usable")?;

        let mut validation = Validation::new(token_header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .context("id_token failed verification")?;

        // Keep the two identity-defining checks explicit so a future Validation change
        // cannot silently widen which identities this adapter accepts.
        if data.claims.iss != self.config.issuer {
            bail!("unexpected token issuer {}", data.claims.iss);
        }
        if !data.claims.aud.contains(&self.config.client_id) {
            bail!("token was issued for a different client");
        }
        if data.claims.sub.is_empty() {
            bail!("token subject is empty");
        }
        if data.claims.sub.len() > 2048 {
            bail!("token subject is unreasonably large");
        }

        Ok(ExternalIdentity {
            namespace: data.claims.iss,
            subject: data.claims.sub,
        })
    }
}

fn validate_jwk(jwk: &Jwk, algorithm: Algorithm) -> Result<()> {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|key_use| key_use != &PublicKeyUse::Signature)
    {
        bail!("OIDC key is not marked for signatures");
    }
    if jwk
        .common
        .key_operations
        .as_ref()
        .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        bail!("OIDC key is not permitted to verify signatures");
    }
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        bail!("symmetric OIDC keys are not accepted");
    }
    if jwk
        .common
        .key_algorithm
        .is_some_and(|declared| declared.to_string() != format!("{algorithm:?}"))
    {
        bail!("OIDC key algorithm does not match the token header");
    }
    Ok(())
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    iss: String,
    aud: Audience,
    // Its presence keeps expiry validation required even though the application does not
    // otherwise use it directly.
    #[allow(dead_code)]
    exp: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

struct OidcState {
    app: Shared,
    adapter: OidcAdapter,
    pending: Mutex<HashMap<String, PendingLogin>>,
}

pub fn router(app: Shared, config: OidcConfig) -> Result<Router> {
    let state = Arc::new(OidcState {
        app,
        adapter: OidcAdapter::new(config)?,
        pending: Mutex::new(HashMap::new()),
    });
    Ok(Router::new()
        .route("/auth/start", get(start))
        .route("/auth/callback", get(callback))
        .with_state(state))
}

#[derive(Deserialize)]
struct StartQuery {
    return_to: Option<String>,
}

async fn start(State(state): State<Arc<OidcState>>, Query(query): Query<StartQuery>) -> Response {
    let now = api::now_secs();
    let verifier = auth::generate_session_token();
    let challenge = data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));
    let login_state = auth::generate_session_token();
    let return_to = safe_return_to(query.return_to.as_deref());

    {
        let mut pending = state.pending.lock().unwrap();
        pending.retain(|_, attempt| attempt.expires_at > now);
        if pending.len() >= MAX_PENDING_LOGINS {
            if let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, attempt)| attempt.expires_at)
                .map(|(key, _)| key.clone())
            {
                pending.remove(&oldest);
            }
        }
        pending.insert(
            login_state.clone(),
            PendingLogin {
                verifier,
                return_to,
                expires_at: now + LOGIN_ATTEMPT_TTL_SECS,
            },
        );
    }

    let mut response = Redirect::temporary(
        state
            .adapter
            .authorization_url(&login_state, &challenge)
            .as_str(),
    )
    .into_response();
    match HeaderValue::from_str(&login_state_cookie(&state.app, &login_state, false)) {
        Ok(cookie) => {
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Err(err) => {
            tracing::error!("could not create OIDC state cookie: {err}");
            login_failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(
    State(state): State<Arc<OidcState>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let mut response = complete_callback(&state, &headers, query).await;
    match HeaderValue::from_str(&login_state_cookie(&state.app, "", true)) {
        Ok(cookie) => {
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Err(err) => {
            tracing::error!("could not clear OIDC state cookie: {err}");
            login_failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn complete_callback(
    state: &OidcState,
    headers: &HeaderMap,
    query: CallbackQuery,
) -> Response {
    let Some(login_state) = query.state.as_deref() else {
        return login_failed(StatusCode::BAD_REQUEST);
    };
    // State in the callback URL is visible to the browser that began the login. Requiring
    // the same value in an HttpOnly cookie prevents an attacker from forwarding their own
    // completed callback URL and logging another browser into the attacker's account.
    if login_state_cookie_value(headers) != Some(login_state) {
        return login_failed(StatusCode::BAD_REQUEST);
    }
    let attempt = {
        let mut pending = state.pending.lock().unwrap();
        pending.remove(login_state)
    };
    let Some(attempt) = attempt else {
        return login_failed(StatusCode::BAD_REQUEST);
    };
    if attempt.expires_at <= api::now_secs() || query.error.is_some() {
        return login_failed(StatusCode::UNAUTHORIZED);
    }
    let Some(code) = query.code.as_deref() else {
        return login_failed(StatusCode::BAD_REQUEST);
    };

    let identity = match state.adapter.authenticate(code, &attempt.verifier).await {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!("OIDC sign-in failed: {err:#}");
            return login_failed(StatusCode::UNAUTHORIZED);
        }
    };
    let session = match api::establish_browser_session(&state.app, identity) {
        Ok(session) => session,
        Err(_) => return login_failed(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let target = if session.handle.is_some() {
        attempt.return_to
    } else {
        "/".to_string()
    };
    let mut response = Redirect::to(&target).into_response();
    match HeaderValue::from_str(&api::browser_session_cookie(&state.app, &session.token)) {
        Ok(cookie) => {
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Err(err) => {
            tracing::error!("could not create browser session cookie: {err}");
            login_failed(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn login_state_cookie(app: &api::AppState, value: &str, clear: bool) -> String {
    format!(
        "devsite_login_state={value}; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age={}{}",
        if clear { 0 } else { LOGIN_ATTEMPT_TTL_SECS },
        if app.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    )
}

fn login_state_cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == "devsite_login_state")
        .map(|(_, value)| value)
}

fn safe_return_to(value: Option<&str>) -> String {
    value
        .filter(|value| {
            value.starts_with('/')
                && !value.starts_with("//")
                && value.bytes().all(|byte| byte.is_ascii_graphic())
                && !value.contains('\\')
                && !value.starts_with("/auth/")
        })
        .unwrap_or("/")
        .to_string()
}

fn login_failed(status: StatusCode) -> Response {
    (
        status,
        Html(
            "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>\
             <main><h1>Sign-in failed.</h1><p>The login could not be verified.</p>\
             <p><a href=/auth/start>Try again</a> · <a href=/>Return home</a></p></main>",
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_cannot_escape_the_site_or_reenter_the_callback() {
        assert_eq!(safe_return_to(Some("/@alice")), "/@alice");
        for unsafe_path in [
            "https://evil.example",
            "//evil.example",
            "/auth/callback",
            "/x\r\n",
            "/x\0",
            "/snowman-☃",
        ] {
            assert_eq!(safe_return_to(Some(unsafe_path)), "/");
        }
    }

    #[test]
    fn audiences_support_both_oidc_encodings() {
        assert!(Audience::One("client".into()).contains("client"));
        assert!(Audience::Many(vec!["other".into(), "client".into()]).contains("client"));
        assert!(!Audience::Many(vec!["other".into()]).contains("client"));
    }

    #[test]
    fn symmetric_provider_algorithms_are_rejected() {
        assert_eq!(parse_algorithms("RS256, ES256").unwrap().len(), 2);
        assert!(parse_algorithms("HS256").is_err());
        assert!(parse_algorithms("").is_err());
    }

    #[test]
    fn callback_state_is_read_only_from_its_bound_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; devsite_login_state=state-123"),
        );
        assert_eq!(login_state_cookie_value(&headers), Some("state-123"));
    }
}
