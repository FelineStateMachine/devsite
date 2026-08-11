//! HTTP surface of the control plane.

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use devsite_proto::capability::KeyBytes;
use devsite_proto::{AccountId, ResourceId};
use serde::{Deserialize, Serialize};

use crate::auth::{self, ShooVerifier};
use crate::db::{Db, ResourceKind};
use crate::issuer::Issuer;
use crate::policy::{can_view, Visibility};
use crate::theme;

pub struct AppState {
    pub db: Mutex<Db>,
    pub issuer: Issuer,
    pub shoo: ShooVerifier,
    pub public_origin: String,
}

pub type Shared = Arc<AppState>;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -- errors -------------------------------------------------------------------

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }
    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "sign in first".into())
    }
    /// Used wherever revealing existence would leak information.
    fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "not found".into())
    }
    fn internal(err: anyhow::Error) -> Self {
        tracing::error!("internal error: {err:#}");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// -- session extraction --------------------------------------------------------

/// Resolve the caller's account from the session cookie or bearer token.
///
/// Returns `None` for anonymous callers rather than erroring, because public profiles are
/// readable without signing in.
fn current_account(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<AccountId>> {
    let token = bearer_token(headers).or_else(|| cookie_token(headers));
    let Some(token) = token else {
        return Ok(None);
    };
    let hash = auth::hash_token(&token);
    let db = state.db.lock().unwrap();
    let account = db
        .session_account(&hash, now_secs())
        .map_err(ApiError::internal)?;
    Ok(account.map(|a| a.id))
}

fn require_account(state: &AppState, headers: &HeaderMap) -> ApiResult<AccountId> {
    current_account(state, headers)?.ok_or_else(ApiError::unauthorized)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_string)
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == "devsite_session")
        .map(|(_, value)| value.to_string())
}

// -- payloads ------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignInRequest {
    pub id_token: String,
}

#[derive(Serialize)]
pub struct SignInResponse {
    pub token: String,
    pub account_id: String,
    pub handle: Option<String>,
}

#[derive(Deserialize)]
pub struct ClaimHandleRequest {
    pub handle: String,
}

#[derive(Deserialize)]
pub struct CreateResourceRequest {
    pub name: String,
    pub kind: String,
    pub visibility: String,
    #[serde(default)]
    pub url: Option<String>,
    /// Handles to share with. Only meaningful when `visibility` is `shared`.
    #[serde(default)]
    pub share_with: Vec<String>,
}

#[derive(Serialize)]
pub struct CreateResourceResponse {
    pub resource_id: String,
}

#[derive(Deserialize)]
pub struct RegisterDaemonRequest {
    pub endpoint_id: String,
}

#[derive(Serialize)]
pub struct ProfileEntry {
    pub resource_id: String,
    pub name: String,
    pub kind: &'static str,
    pub visibility: &'static str,
    pub url: Option<String>,
    /// Present only on "shared with me" entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_handle: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileResponse {
    pub handle: String,
    pub is_owner: bool,
    pub entries: Vec<ProfileEntry>,
    pub shared_with_me: Vec<ProfileEntry>,
    /// The owner's theme: validated `--pico-*` assignments, in the order they
    /// were written. The page turns these into one rule scoped to the profile.
    pub theme: Vec<theme::Declaration>,
}

#[derive(Deserialize)]
pub struct ThemeRequest {
    /// Declarations only — `--pico-border-radius: 0.5rem;` and so on. Anything
    /// that is not on the whitelist is a 400 with a reason, never a silent drop.
    pub css: String,
}

#[derive(Serialize)]
pub struct ThemeResponse {
    /// The theme as stored, after normalisation.
    pub css: String,
    pub theme: Vec<theme::Declaration>,
}

#[derive(Deserialize)]
pub struct CapabilityRequest {
    pub resource_id: String,
    pub browser_endpoint_id: String,
}

#[derive(Serialize)]
pub struct CapabilityResponse {
    /// base64url of the postcard-encoded signed capability.
    pub capability: String,
    /// Who to present it to. Not where they are — the browser resolves that
    /// through iroh's address lookup, from the daemon's own published record.
    pub daemon_endpoint_id: String,
}

// -- routes --------------------------------------------------------------------

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/api/config", get(config))
        .route("/api/pubkey", get(pubkey))
        .route("/api/auth/session", post(sign_in))
        .route("/api/me", get(me))
        .route("/api/profile", post(claim_handle))
        .route("/api/resources", post(create_resource).get(list_resources))
        .route("/api/daemon", axum::routing::put(register_daemon))
        .route("/api/theme", get(read_theme).put(write_theme))
        .route("/api/theme/properties", get(theme_properties))
        .route("/api/profile/{handle}", get(profile))
        .route("/api/capability", post(capability))
        .with_state(state)
}

/// Public configuration the browser needs to start a sign-in.
async fn config(State(state): State<Shared>) -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": auth::ISSUER,
        "public_origin": state.public_origin,
        "redirect_uri": format!("{}/auth/callback", state.public_origin),
    }))
}

/// The capability-signing public key, pinned by daemons at login.
async fn pubkey(State(state): State<Shared>) -> impl IntoResponse {
    Json(serde_json::json!({ "public_key": state.issuer.public_key_hex() }))
}

async fn sign_in(
    State(state): State<Shared>,
    Json(body): Json<SignInRequest>,
) -> ApiResult<Response> {
    let claims = state
        .shoo
        .verify(&body.id_token)
        .await
        .map_err(|err| {
            tracing::warn!("rejected an id_token: {err:#}");
            ApiError(StatusCode::UNAUTHORIZED, "invalid sign-in token".into())
        })?;

    let now = now_secs();
    let token = auth::generate_session_token();
    let (account_id, handle) = {
        let db = state.db.lock().unwrap();
        let account = db
            .upsert_account(&claims.sub, now)
            .map_err(ApiError::internal)?;
        db.create_session(
            &auth::hash_token(&token),
            account.id,
            now + auth::SESSION_LIFETIME_SECS,
        )
        .map_err(ApiError::internal)?;
        db.purge_expired_sessions(now).ok();
        (account.id, account.handle)
    };

    // HttpOnly so page scripts cannot read it; SameSite=Lax so it survives the OAuth
    // redirect back from Shoo without being sent on cross-site POSTs.
    let cookie = format!(
        "devsite_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        auth::SESSION_LIFETIME_SECS,
        if state.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    );

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(SignInResponse {
            token,
            account_id: account_id.to_string(),
            handle,
        }),
    )
        .into_response())
}

async fn me(State(state): State<Shared>, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    let id = require_account(&state, &headers)?;
    let db = state.db.lock().unwrap();
    let account = db
        .account_by_id(id)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(serde_json::json!({
        "account_id": account.id.to_string(),
        "handle": account.handle,
    })))
}

async fn claim_handle(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ClaimHandleRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = require_account(&state, &headers)?;
    let handle = auth::validate_handle(&body.handle).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let db = state.db.lock().unwrap();
    if let Some(existing) = db.account_by_handle(&handle).map_err(ApiError::internal)? {
        if existing.id != id {
            return Err(ApiError::bad_request("that handle is taken"));
        }
    }
    db.set_handle(id, &handle).map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({ "handle": handle })))
}

async fn create_resource(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<CreateResourceRequest>,
) -> ApiResult<impl IntoResponse> {
    let owner = require_account(&state, &headers)?;

    let kind = match body.kind.as_str() {
        "link" => ResourceKind::Link,
        "service" => ResourceKind::Service,
        other => return Err(ApiError::bad_request(format!("unknown kind `{other}`"))),
    };
    let visibility = Visibility::parse(&body.visibility)
        .ok_or_else(|| ApiError::bad_request("visibility must be public, private or shared"))?;

    // A link needs a URL; a service must not carry one. The local origin of a service stays
    // in the owner's daemon config and is never uploaded.
    match kind {
        ResourceKind::Link if body.url.is_none() => {
            return Err(ApiError::bad_request("a link needs a url"))
        }
        ResourceKind::Service if body.url.is_some() => {
            return Err(ApiError::bad_request(
                "a service's local origin stays on your machine and must not be sent here",
            ))
        }
        _ => {}
    }

    let db = state.db.lock().unwrap();

    // Resolve every share target *before* creating anything. Creating first and failing
    // partway leaves an orphaned resource on the profile that the owner's daemon knows
    // nothing about — it would advertise itself and then refuse every request.
    let mut viewers = Vec::new();
    for handle in &body.share_with {
        let handle =
            auth::validate_handle(handle).map_err(|e| ApiError::bad_request(e.to_string()))?;
        let viewer = db
            .account_by_handle(&handle)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::bad_request(format!("no such user @{handle}")))?;
        viewers.push(viewer.id);
    }

    let resource = db
        .create_resource(owner, &body.name, kind, visibility, body.url.as_deref(), now_secs())
        .map_err(ApiError::internal)?;

    for viewer in viewers {
        db.share_with(resource, viewer).map_err(ApiError::internal)?;
    }

    Ok(Json(CreateResourceResponse {
        resource_id: resource.to_string(),
    }))
}

async fn list_resources(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let owner = require_account(&state, &headers)?;
    let db = state.db.lock().unwrap();
    let resources = db.resources_owned_by(owner).map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "resources": resources.iter().map(|r| serde_json::json!({
            "resource_id": r.id.to_string(),
            "name": r.name,
            "kind": r.kind.as_str(),
            "visibility": r.visibility.as_str(),
            "url": r.url,
        })).collect::<Vec<_>>()
    })))
}

/// Record which endpoint id this account's daemon answers on.
///
/// Called once when a daemon starts, not on a timer. The id is stable across
/// restarts, and where that endpoint can be reached is published by the daemon
/// itself and resolved by the browser — the control plane is not in the
/// addressing path and does not want to be.
async fn register_daemon(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<RegisterDaemonRequest>,
) -> ApiResult<impl IntoResponse> {
    let account = require_account(&state, &headers)?;
    // Validated before storing: a malformed id would be handed to browsers as
    // something to go looking for, and fail somewhere much less obvious.
    if parse_endpoint_id(&body.endpoint_id).is_none() {
        return Err(ApiError::bad_request("endpoint_id is not a 32 byte hex key"));
    }

    let db = state.db.lock().unwrap();
    db.register_daemon(account, &body.endpoint_id)
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// -- themes --------------------------------------------------------------------

/// The properties a theme may set, and what each one accepts.
///
/// Served by the same binary that enforces the list, so the CLI, the website and
/// the docs cannot drift from what is actually accepted.
async fn theme_properties() -> impl IntoResponse {
    Json(serde_json::json!({
        "properties": theme::properties()
            .map(|(name, accepts)| serde_json::json!({ "name": name, "accepts": accepts }))
            .collect::<Vec<_>>()
    }))
}

async fn read_theme(State(state): State<Shared>, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    let account = require_account(&state, &headers)?;
    let css = {
        let db = state.db.lock().unwrap();
        db.custom_css(account).map_err(ApiError::internal)?
    };
    let css = css.unwrap_or_default();
    Ok(Json(ThemeResponse {
        theme: theme::parse(&css).unwrap_or_default(),
        css,
    }))
}

async fn write_theme(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ThemeRequest>,
) -> ApiResult<impl IntoResponse> {
    let account = require_account(&state, &headers)?;

    // Validated here, once, before anything is stored. Every later read — the
    // profile page, the CLI, this endpoint — can then treat the column as
    // already-checked rather than re-deciding what is safe.
    let declarations = theme::parse(&body.css).map_err(ApiError::bad_request)?;
    let css = theme::to_css(&declarations);

    let db = state.db.lock().unwrap();
    db.set_custom_css(account, (!css.is_empty()).then_some(css.as_str()))
        .map_err(ApiError::internal)?;

    Ok(Json(ThemeResponse {
        css,
        theme: declarations,
    }))
}

async fn profile(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let viewer = current_account(&state, &headers)?;
    let handle = handle.trim_start_matches('@').to_ascii_lowercase();

    let db = state.db.lock().unwrap();
    let owner = db
        .account_by_handle(&handle)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;

    let mut entries = Vec::new();
    for resource in db.resources_owned_by(owner.id).map_err(ApiError::internal)? {
        let shared_with = db.shared_with(resource.id).map_err(ApiError::internal)?;
        // The single choke point. A resource that fails here is not merely hidden from the
        // rendering — it never enters the response at all.
        if !can_view(viewer, owner.id, resource.visibility, &shared_with) {
            continue;
        }
        entries.push(to_entry(&resource, None));
    }

    // "Shared with me" belongs on your own profile, not on everyone else's. Listing it on
    // @dami's page would also show Frank the same Agent entry twice.
    let mut shared_with_me = Vec::new();
    if let Some(viewer_id) = viewer.filter(|v| *v == owner.id) {
        for resource in db
            .resources_shared_with(viewer_id)
            .map_err(ApiError::internal)?
        {
            let shared = db.shared_with(resource.id).map_err(ApiError::internal)?;
            if !can_view(viewer, resource.owner_id, resource.visibility, &shared) {
                continue;
            }
            let owner_account = db
                .account_by_id(resource.owner_id)
                .map_err(ApiError::internal)?;
            shared_with_me.push(to_entry(&resource, owner_account.and_then(|a| a.handle)));
        }
    }

    // Stored themes are canonical, so re-parsing them here is cheap and always
    // succeeds. It is not merely a formality: if a property is ever retired from
    // the whitelist, a profile styled with it degrades to the default rather
    // than serving a rule the current build no longer stands behind.
    let theme = match db.custom_css(owner.id).map_err(ApiError::internal)? {
        Some(css) => theme::parse(&css).unwrap_or_else(|err| {
            tracing::warn!(handle = %handle, "stored theme no longer validates: {err}");
            Vec::new()
        }),
        None => Vec::new(),
    };

    Ok(Json(ProfileResponse {
        handle,
        is_owner: viewer == Some(owner.id),
        entries,
        shared_with_me,
        theme,
    }))
}

fn to_entry(resource: &crate::db::Resource, owner_handle: Option<String>) -> ProfileEntry {
    ProfileEntry {
        resource_id: resource.id.to_string(),
        name: resource.name.clone(),
        kind: resource.kind.as_str(),
        visibility: resource.visibility.as_str(),
        url: resource.url.clone(),
        owner_handle,
    }
}

/// Issue a capability, if and only if the caller may view the resource.
///
/// Denials are 404 rather than 403 throughout: a 403 would confirm that a resource id
/// exists, which is enough to enumerate someone's private services.
async fn capability(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<CapabilityRequest>,
) -> ApiResult<impl IntoResponse> {
    let viewer = require_account(&state, &headers)?;

    let resource_id = ResourceId::from_str(&body.resource_id).map_err(|_| ApiError::not_found())?;
    let browser_key =
        parse_endpoint_id(&body.browser_endpoint_id).ok_or_else(|| ApiError::bad_request("browser_endpoint_id is not a 32 byte hex key"))?;

    let (resource, endpoint_id) = {
        let db = state.db.lock().unwrap();
        let resource = db
            .resource(resource_id)
            .map_err(ApiError::internal)?
            .ok_or_else(ApiError::not_found)?;
        let shared_with = db.shared_with(resource_id).map_err(ApiError::internal)?;

        if !can_view(Some(viewer), resource.owner_id, resource.visibility, &shared_with) {
            tracing::warn!(
                viewer = %viewer,
                resource = %resource_id,
                "refused a capability request"
            );
            return Err(ApiError::not_found());
        }
        if resource.kind != ResourceKind::Service {
            return Err(ApiError::bad_request("that resource is a link, not a service"));
        }
        let endpoint_id = db
            .daemon_endpoint(resource.owner_id)
            .map_err(ApiError::internal)?;
        (resource, endpoint_id)
    };

    // The only thing that can be answered from here. Whether the daemon is
    // *running* is not knowable at this end without asking it, so the browser
    // asks it directly and reports what it finds. This case is the narrower one:
    // no daemon has ever registered, so there is not even an address to try.
    let endpoint_id = endpoint_id.ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "no daemon has been registered for that service — run `devsite daemon run`".into(),
        )
    })?;

    let audience = parse_endpoint_id(&endpoint_id)
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("stored daemon endpoint id is invalid")))?;

    let capability = state
        .issuer
        .issue(viewer, resource.id, audience, browser_key, now_secs())
        .map_err(ApiError::internal)?;

    Ok(Json(CapabilityResponse {
        capability: data_encoding::BASE64URL_NOPAD.encode(&capability.to_bytes()),
        daemon_endpoint_id: endpoint_id,
    }))
}

/// Parse a hex iroh endpoint id into raw key bytes.
fn parse_endpoint_id(text: &str) -> Option<KeyBytes> {
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.trim().as_bytes())
        .ok()?;
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_endpoint_id() {
        let hex = "89ef8f68b58d5dbfa8501010a0f2ea3afaf80952f04e6767fadbf6d16658e7a0";
        assert!(parse_endpoint_id(hex).is_some());
        assert!(parse_endpoint_id(&hex.to_uppercase()).is_some());
    }

    #[test]
    fn rejects_endpoint_ids_of_the_wrong_shape() {
        for bad in ["", "abcd", "zz", "89ef8f68b58d5dbfa8501010a0f2ea3afaf80952f04e6767fadbf6d16658e7"] {
            assert!(parse_endpoint_id(bad).is_none(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn reads_the_session_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=dark; devsite_session=abc123; other=x".parse().unwrap(),
        );
        assert_eq!(cookie_token(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn prefers_an_explicit_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer cli-token".parse().unwrap());
        assert_eq!(bearer_token(&headers).as_deref(), Some("cli-token"));
    }
}
