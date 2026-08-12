//! HTTP surface of the control plane.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use devsite_proto::capability::KeyBytes;
use devsite_proto::{AccountId, ResourceId};
use serde::{Deserialize, Serialize};

use crate::auth::{self, ExternalIdentity};
use crate::db::{Db, MachineAuthentication, ResourceKind, ShareStatus};
use crate::issuer::Issuer;
use crate::policy::{can_view, Visibility};
use crate::theme;

pub struct AppState {
    pub db: Mutex<Db>,
    pub rate_limits: Mutex<RateLimits>,
    pub issuer: Issuer,
    pub identity_namespace: String,
    pub public_origin: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateClass {
    Session,
    Mutation,
    Credential,
    Capability,
}

impl RateClass {
    fn limit(self) -> u32 {
        match self {
            Self::Session => 12,
            Self::Mutation => 120,
            Self::Credential => 20,
            Self::Capability => 300,
        }
    }
}

#[derive(Default)]
pub struct RateLimits {
    windows: HashMap<(AccountId, RateClass), RateWindow>,
}

struct RateWindow {
    started_at: u64,
    requests: u32,
}

impl RateLimits {
    fn check(&mut self, account: AccountId, class: RateClass, now: u64) -> bool {
        const WINDOW_SECS: u64 = 60;
        // One small entry per active account/class. Expired entries from users
        // who never return are discarded opportunistically.
        if self.windows.len() > 4096 {
            self.windows
                .retain(|_, window| now.saturating_sub(window.started_at) < WINDOW_SECS);
        }
        let window = self.windows.entry((account, class)).or_insert(RateWindow {
            started_at: now,
            requests: 0,
        });
        if now.saturating_sub(window.started_at) >= WINDOW_SECS {
            window.started_at = now;
            window.requests = 0;
        }
        if window.requests >= class.limit() {
            return false;
        }
        window.requests += 1;
        true
    }
}

pub type Shared = Arc<AppState>;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -- errors -------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }
    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "sign in first".into())
    }
    fn too_many_requests() -> Self {
        Self(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests — try again shortly".into(),
        )
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
    let now = now_secs();
    let db = state.db.lock().unwrap();
    if let Some(token) = bearer_token(headers) {
        let hash = auth::hash_token(&token);
        // Browser sessions remain accepted as bearer tokens for local operator
        // workflows, but installed CLIs use independently revocable credentials.
        let account = db
            .machine_authentication(&hash, now)
            .map_err(ApiError::internal)?
            .map(|machine| machine.account)
            .or(db.session_account(&hash, now).map_err(ApiError::internal)?);
        return Ok(account.map(|a| a.id));
    }
    let Some(token) = cookie_token(headers) else {
        return Ok(None);
    };
    let account = db
        .session_account(&auth::hash_token(&token), now)
        .map_err(ApiError::internal)?;
    Ok(account.map(|a| a.id))
}

fn require_account(state: &AppState, headers: &HeaderMap) -> ApiResult<AccountId> {
    current_account(state, headers)?.ok_or_else(ApiError::unauthorized)
}

/// Dashboard-only operations require the browser's HttpOnly session cookie. A
/// stolen machine credential can manage the profile, but cannot mint siblings
/// or revoke the owner's remaining ways back in.
fn require_browser_account(state: &AppState, headers: &HeaderMap) -> ApiResult<AccountId> {
    let token = cookie_token(headers).ok_or_else(ApiError::unauthorized)?;
    let db = state.db.lock().unwrap();
    db.session_account(&auth::hash_token(&token), now_secs())
        .map_err(ApiError::internal)?
        .map(|account| account.id)
        .ok_or_else(ApiError::unauthorized)
}

fn require_machine(state: &AppState, headers: &HeaderMap) -> ApiResult<MachineAuthentication> {
    let token = bearer_token(headers).ok_or_else(ApiError::unauthorized)?;
    state
        .db
        .lock()
        .unwrap()
        .machine_authentication(&auth::hash_token(&token), now_secs())
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::unauthorized)
}

fn check_rate(state: &AppState, account: AccountId, class: RateClass) -> ApiResult<()> {
    if state
        .rate_limits
        .lock()
        .unwrap()
        .check(account, class, now_secs())
    {
        Ok(())
    } else {
        Err(ApiError::too_many_requests())
    }
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
    /// The folder to file it under. Absent means loose on the profile — and
    /// absent on a re-add means "take it out of the folder it was in", because a
    /// command names the whole state of the thing it names.
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Serialize)]
pub struct CreateResourceResponse {
    pub resource_id: String,
    pub plan: ResourcePlan,
}

#[derive(Serialize)]
pub struct ResourcePlanResponse {
    pub plan: ResourcePlan,
}

#[derive(Debug, Serialize)]
pub struct ResourcePlan {
    pub operation: &'static str,
    pub target: ResourcePlanTarget,
    pub changes: Vec<ResourcePlanChange>,
    pub recipient_changes: Vec<RecipientPlanChange>,
    pub effects: Vec<ResourcePlanEffect>,
}

#[derive(Debug, Serialize)]
pub struct ResourcePlanTarget {
    pub resource_id: Option<String>,
    pub kind: &'static str,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct ResourcePlanChange {
    pub field: &'static str,
    pub from: serde_json::Value,
    pub to: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct RecipientPlanChange {
    pub handle: String,
    pub from: Option<&'static str>,
    pub to: Option<&'static str>,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ResourcePlanEffect {
    pub code: &'static str,
    pub handles: Vec<String>,
}

#[derive(Deserialize)]
pub struct RegisterDaemonRequest {
    pub proof: String,
}

#[derive(Deserialize)]
pub struct EnrollMachineRequest {
    pub endpoint_id: String,
    pub proof: String,
}

#[derive(Deserialize)]
pub struct SetSharesRequest {
    #[serde(default)]
    pub share_with: Vec<String>,
}

#[derive(Deserialize)]
pub struct ProfileSettingsRequest {
    pub private_only: bool,
}

#[derive(Deserialize)]
pub struct CreateMachineCredentialRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct ProfileEntry {
    pub resource_id: String,
    pub name: String,
    pub kind: &'static str,
    pub visibility: &'static str,
    pub url: Option<String>,
    pub folder: Option<String>,
    /// Present only on "shared with me" entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_handle: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileResponse {
    pub handle: String,
    pub entries: Vec<ProfileEntry>,
    pub shared_with_me: Vec<ProfileEntry>,
    /// The owner's presentation: validated `--pico-*` theme assignments and
    /// `--devsite-*` layout settings, in the order they were written. The page
    /// turns only the Pico declarations into a scoped rule.
    pub theme: Vec<theme::Declaration>,
}

#[derive(Deserialize)]
pub struct ThemeRequest {
    /// Declarations only — `--pico-border-radius: 0.5rem;`,
    /// `--devsite-folders: closed;`, and so on. Anything outside the whitelist
    /// is a 400 with a reason, never a silent drop.
    pub css: String,
}

#[derive(Serialize)]
pub struct ThemeResponse {
    /// The theme as stored, after normalisation.
    pub css: String,
    pub theme: Vec<theme::Declaration>,
}

#[derive(Serialize)]
pub struct ConnectionTicketResponse {
    pub ticket: String,
    pub expires_at: u64,
}

#[derive(Deserialize)]
pub struct RedeemTicketRequest {
    pub ticket: String,
    pub client_endpoint_id: String,
}

#[derive(Serialize)]
pub struct RedeemTicketResponse {
    pub session_token: String,
    pub resource_id: String,
    pub name: String,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct CapabilityResponse {
    /// base64url of the postcard-encoded signed capability.
    pub capability: String,
    /// Who to present it to. Not where they are — the client resolves that
    /// through iroh's address lookup, from the daemon's own published record.
    pub daemon_endpoint_id: String,
}

// -- routes --------------------------------------------------------------------

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/api/config", get(config))
        .route("/api/pubkey", get(pubkey))
        .route("/api/auth/session", delete(sign_out))
        .route("/api/me", get(me))
        .route("/api/profile", post(claim_handle))
        .route("/api/resources", post(create_resource).get(list_resources))
        .route("/api/resources/plan", post(plan_resource))
        .route("/api/resources/{id}", delete(delete_resource))
        .route("/api/resources/{id}/shares", put(set_resource_shares))
        .route("/api/share-invitations", get(list_share_invitations))
        .route(
            "/api/share-invitations/{id}/accept",
            post(accept_share_invitation),
        )
        .route(
            "/api/share-invitations/{id}",
            delete(decline_share_invitation),
        )
        .route("/api/daemon", get(daemon_info).put(register_daemon))
        .route("/api/daemon/authorizations", get(daemon_authorizations))
        .route("/api/machine/enroll", put(enroll_machine))
        .route(
            "/api/profile/settings",
            get(profile_settings).put(set_profile_settings),
        )
        .route(
            "/api/machine-credentials",
            get(list_machine_credentials).post(create_machine_credential),
        )
        .route(
            "/api/machine-credentials/{id}",
            delete(revoke_machine_credential),
        )
        .route("/api/theme", get(read_theme).put(write_theme))
        .route("/api/theme/properties", get(theme_properties))
        .route("/api/profile/{handle}", get(profile))
        .route("/api/services/{id}/ticket", post(create_connection_ticket))
        .route("/api/tickets/redeem", post(redeem_connection_ticket))
        .route("/api/tunnel/session", delete(delete_tunnel_session))
        .route("/api/tunnel/capability", post(tunnel_capability))
        .with_state(state)
}

/// Public configuration the browser needs to start a sign-in.
async fn config(State(state): State<Shared>) -> impl IntoResponse {
    Json(serde_json::json!({
        // `issuer` stays as a compatibility alias for older clients that displayed it.
        "issuer": state.identity_namespace,
        "auth": {
            "namespace": state.identity_namespace,
            "start_url": "/auth/start",
        },
        "public_origin": state.public_origin,
        "redirect_uri": format!("{}/auth/callback", state.public_origin),
        "api_version": 3,
        "minimum_cli_version": "0.3.0",
        "server_version": env!("CARGO_PKG_VERSION"),
        "daemon_protocol": String::from_utf8_lossy(devsite_proto::ALPN),
    }))
}

/// The capability-signing public key, pinned by daemons at login.
async fn pubkey(State(state): State<Shared>) -> impl IntoResponse {
    Json(serde_json::json!({ "public_key": state.issuer.public_key_hex() }))
}

pub(crate) struct EstablishedBrowserSession {
    pub token: String,
    pub handle: Option<String>,
}

/// Application port shared by every login adapter: a verified external identity enters;
/// an opaque, provider-independent browser session comes out.
pub(crate) fn establish_browser_session(
    state: &AppState,
    identity: ExternalIdentity,
) -> ApiResult<EstablishedBrowserSession> {
    let now = now_secs();
    let token = auth::generate_session_token();
    let (account_id, handle) = {
        let db = state.db.lock().unwrap();
        let account = db
            .upsert_account(&identity.namespace, &identity.subject, now)
            .map_err(ApiError::internal)?;
        (account.id, account.handle)
    };
    check_rate(state, account_id, RateClass::Session)?;
    {
        let db = state.db.lock().unwrap();
        db.create_session(
            &auth::hash_token(&token),
            account_id,
            now + auth::SESSION_LIFETIME_SECS,
        )
        .map_err(ApiError::internal)?;
        db.purge_expired_sessions(now).ok();
    }

    Ok(EstablishedBrowserSession { token, handle })
}

pub(crate) fn browser_session_cookie(state: &AppState, token: &str) -> String {
    // HttpOnly so page scripts cannot read it; SameSite=Lax so it survives an identity
    // provider redirect without being sent on cross-site POSTs.
    format!(
        "devsite_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        auth::SESSION_LIFETIME_SECS,
        if state.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    )
}

async fn sign_out(State(state): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = cookie_token(&headers) {
        state
            .db
            .lock()
            .unwrap()
            .delete_session(&auth::hash_token(&token))
            .map_err(ApiError::internal)?;
    }

    let cookie = format!(
        "devsite_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if state.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    );
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

async fn me(State(state): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    let Some(id) = current_account(&state, &headers)? else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let db = state.db.lock().unwrap();
    let account = db
        .account_by_id(id)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(serde_json::json!({
        "account_id": account.id.to_string(),
        "handle": account.handle,
    }))
    .into_response())
}

async fn claim_handle(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ClaimHandleRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = require_account(&state, &headers)?;
    check_rate(&state, id, RateClass::Mutation)?;
    let handle =
        auth::validate_handle(&body.handle).map_err(|e| ApiError::bad_request(e.to_string()))?;

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
    check_rate(&state, owner, RateClass::Mutation)?;
    let mut db = state.db.lock().unwrap();
    let mut prepared = prepare_resource(&db, owner, &body)?;

    let resource = db
        .create_resource(
            owner,
            &prepared.name,
            prepared.kind,
            prepared.visibility,
            prepared.url.as_deref(),
            prepared.folder.as_deref(),
            now_secs(),
        )
        .map_err(ApiError::internal)?;

    // The share list this request names is the whole share list afterwards.
    // Re-running `service host --share @carol` means Carol is the invited recipient,
    // not Carol plus whoever was named the last time it ran.
    db.set_shares(resource, &prepared.viewers)
        .map_err(ApiError::internal)?;
    prepared.plan.target.resource_id = Some(resource.to_string());

    Ok(Json(CreateResourceResponse {
        resource_id: resource.to_string(),
        plan: prepared.plan,
    }))
}

async fn plan_resource(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<CreateResourceRequest>,
) -> ApiResult<impl IntoResponse> {
    let owner = require_account(&state, &headers)?;
    // Planning resolves account handles and therefore uses the same bounded
    // rate class as applying a mutation.
    check_rate(&state, owner, RateClass::Mutation)?;
    let db = state.db.lock().unwrap();
    let prepared = prepare_resource(&db, owner, &body)?;
    Ok(Json(ResourcePlanResponse {
        plan: prepared.plan,
    }))
}

struct PreparedResource {
    name: String,
    kind: ResourceKind,
    visibility: Visibility,
    url: Option<String>,
    folder: Option<String>,
    viewers: Vec<AccountId>,
    plan: ResourcePlan,
}

fn prepare_resource(
    db: &Db,
    owner: AccountId,
    body: &CreateResourceRequest,
) -> ApiResult<PreparedResource> {
    let name = validate_resource_name(&body.name)?.to_string();
    let kind = match body.kind.as_str() {
        "link" => ResourceKind::Link,
        "service" => ResourceKind::Service,
        other => return Err(ApiError::bad_request(format!("unknown kind `{other}`"))),
    };
    let visibility = Visibility::parse(&body.visibility)
        .ok_or_else(|| ApiError::bad_request("visibility must be public, private or shared"))?;
    validate_resource_visibility(kind, visibility)?;
    if visibility != Visibility::Shared && !body.share_with.is_empty() {
        return Err(ApiError::bad_request(
            "share_with is only valid when visibility is shared",
        ));
    }

    // A link needs a URL; a service must not carry one. The local TCP target stays
    // in the owner's daemon config and is never uploaded.
    let url = match kind {
        ResourceKind::Link if body.url.is_none() => {
            return Err(ApiError::bad_request("a link needs a url"))
        }
        ResourceKind::Link => Some(validate_public_url(body.url.as_deref().unwrap())?),
        ResourceKind::Service if body.url.is_some() => {
            return Err(ApiError::bad_request(
                "a service's local target stays on your machine and must not be sent here",
            ))
        }
        ResourceKind::Service => None,
    };
    let folder = validate_folder(body.folder.as_deref())?;

    let existing = db
        .resources_owned_by(owner)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|resource| resource.name == name && resource.kind == kind);
    if !db
        .resource_named(owner, &name, kind)
        .map_err(ApiError::internal)?
        && db.resource_count(owner).map_err(ApiError::internal)? >= MAX_RESOURCES
    {
        return Err(ApiError::bad_request(format!(
            "a profile may contain at most {MAX_RESOURCES} resources"
        )));
    }

    // Resolve every share target before either planning or creating anything.
    let viewers = resolve_share_accounts(db, owner, &body.share_with)?;
    let desired_handles = viewers
        .iter()
        .map(|viewer| {
            db.account_by_id(*viewer)
                .map_err(ApiError::internal)?
                .and_then(|account| account.handle)
                .ok_or_else(|| ApiError::bad_request("a share recipient no longer has a handle"))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let plan = build_resource_plan(
        db,
        existing.as_ref(),
        &name,
        kind,
        visibility,
        url.as_deref(),
        folder.as_deref(),
        &desired_handles,
    )?;

    Ok(PreparedResource {
        name,
        kind,
        visibility,
        url,
        folder,
        viewers,
        plan,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_resource_plan(
    db: &Db,
    existing: Option<&crate::db::Resource>,
    name: &str,
    kind: ResourceKind,
    visibility: Visibility,
    url: Option<&str>,
    folder: Option<&str>,
    desired_handles: &[String],
) -> ApiResult<ResourcePlan> {
    let mut changes = Vec::new();
    let current_visibility = existing.map(|resource| resource.visibility.as_str());
    let current_url = existing.and_then(|resource| resource.url.as_deref());
    let current_folder = existing.and_then(|resource| resource.folder.as_deref());
    for (field, from, to) in [
        (
            "visibility",
            serde_json::to_value(current_visibility).unwrap(),
            serde_json::to_value(Some(visibility.as_str())).unwrap(),
        ),
        (
            "url",
            serde_json::to_value(current_url).unwrap(),
            serde_json::to_value(url).unwrap(),
        ),
        (
            "folder",
            serde_json::to_value(current_folder).unwrap(),
            serde_json::to_value(folder).unwrap(),
        ),
    ] {
        if from != to {
            changes.push(ResourcePlanChange { field, from, to });
        }
    }

    let existing_recipients = match existing {
        Some(resource) => db
            .share_recipients(resource.id)
            .map_err(ApiError::internal)?,
        None => Vec::new(),
    };
    let desired = desired_handles
        .iter()
        .map(|handle| handle.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let existing_names = existing_recipients
        .iter()
        .map(|recipient| recipient.handle.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let destination_changed =
        kind == ResourceKind::Link && existing.is_some() && current_url != url;
    let mut recipient_changes = Vec::new();
    let mut reapproval = Vec::new();
    let mut access_revoked = Vec::new();
    let mut invitations_withdrawn = Vec::new();
    let mut invited = Vec::new();

    for recipient in &existing_recipients {
        let wanted = desired.contains(&recipient.handle.to_ascii_lowercase());
        if !wanted {
            recipient_changes.push(RecipientPlanChange {
                handle: recipient.handle.clone(),
                from: Some(recipient.status.as_str()),
                to: None,
                reason: "recipient_removed",
            });
            match recipient.status {
                ShareStatus::Accepted => access_revoked.push(recipient.handle.clone()),
                ShareStatus::Pending => invitations_withdrawn.push(recipient.handle.clone()),
                ShareStatus::Declined => {}
            }
        } else if destination_changed && recipient.status == ShareStatus::Accepted {
            recipient_changes.push(RecipientPlanChange {
                handle: recipient.handle.clone(),
                from: Some("accepted"),
                to: Some("pending"),
                reason: "destination_changed",
            });
            reapproval.push(recipient.handle.clone());
        }
    }
    for handle in desired_handles {
        if !existing_names.contains(&handle.to_ascii_lowercase()) {
            recipient_changes.push(RecipientPlanChange {
                handle: handle.clone(),
                from: None,
                to: Some("pending"),
                reason: "recipient_added",
            });
            invited.push(handle.clone());
        }
    }

    let mut effects = Vec::new();
    for (code, handles) in [
        ("recipient_reapproval_required", reapproval),
        ("accepted_access_revoked", access_revoked),
        ("pending_invitations_withdrawn", invitations_withdrawn),
        ("recipients_invited", invited),
    ] {
        if !handles.is_empty() {
            effects.push(ResourcePlanEffect { code, handles });
        }
    }

    let operation = if existing.is_none() {
        "create"
    } else if changes.is_empty() && recipient_changes.is_empty() {
        "noop"
    } else {
        "update"
    };
    Ok(ResourcePlan {
        operation,
        target: ResourcePlanTarget {
            resource_id: existing.map(|resource| resource.id.to_string()),
            kind: kind.as_str(),
            name: name.to_string(),
        },
        changes,
        recipient_changes,
        effects,
    })
}

fn validate_resource_visibility(kind: ResourceKind, visibility: Visibility) -> ApiResult<()> {
    match (kind, visibility) {
        (ResourceKind::Link, Visibility::Public | Visibility::Private | Visibility::Shared)
        | (ResourceKind::Service, Visibility::Private | Visibility::Shared) => {}
        (ResourceKind::Service, Visibility::Public) => {
            return Err(ApiError::bad_request(
                "TCP services must be private or shared with specific users",
            ))
        }
    }
    Ok(())
}

const MAX_RESOURCES: usize = 100;
const MAX_SHARES: usize = 25;
const MAX_RESOURCE_NAME: usize = 80;
const MAX_PUBLIC_URL: usize = 2048;

fn validate_resource_name(name: &str) -> ApiResult<&str> {
    if name.trim() != name || name.is_empty() {
        return Err(ApiError::bad_request(
            "a resource name must not be blank or have leading or trailing whitespace",
        ));
    }
    if name.chars().count() > MAX_RESOURCE_NAME {
        return Err(ApiError::bad_request(format!(
            "a resource name may be at most {MAX_RESOURCE_NAME} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "a resource name may not contain control characters",
        ));
    }
    Ok(name)
}

fn validate_public_url(value: &str) -> ApiResult<String> {
    if value.len() > MAX_PUBLIC_URL {
        return Err(ApiError::bad_request(format!(
            "a link URL may be at most {MAX_PUBLIC_URL} bytes"
        )));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| ApiError::bad_request("a link URL must be a valid absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(ApiError::bad_request(
            "a link URL must use http or https and name a host",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ApiError::bad_request(
            "a link URL may not contain embedded credentials",
        ));
    }
    Ok(parsed.to_string())
}

fn resolve_share_accounts(
    db: &Db,
    owner: AccountId,
    handles: &[String],
) -> ApiResult<Vec<AccountId>> {
    if handles.len() > MAX_SHARES {
        return Err(ApiError::bad_request(format!(
            "a resource may be shared with at most {MAX_SHARES} people"
        )));
    }
    let mut seen = HashSet::new();
    let mut viewers = Vec::new();
    for handle in handles {
        let handle =
            auth::validate_handle(handle).map_err(|e| ApiError::bad_request(e.to_string()))?;
        let viewer = db
            .account_by_handle(&handle)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::bad_request(format!("no such user @{handle}")))?;
        if viewer.id == owner {
            return Err(ApiError::bad_request(
                "you do not need to share a resource with yourself",
            ));
        }
        if seen.insert(viewer.id) {
            viewers.push(viewer.id);
        }
    }
    Ok(viewers)
}

/// Check a folder name, treating blank as none.
///
/// A folder has no existence of its own — it is this string, repeated across the
/// resources that share it — so "" and absent have to mean the same thing, or a
/// profile would grow a nameless fold that nothing could remove.
fn validate_folder(folder: Option<&str>) -> ApiResult<Option<String>> {
    let Some(folder) = folder.map(str::trim).filter(|f| !f.is_empty()) else {
        return Ok(None);
    };
    if folder.chars().count() > theme::MAX_FOLDER_NAME {
        return Err(ApiError::bad_request(format!(
            "a folder name may be at most {} characters",
            theme::MAX_FOLDER_NAME
        )));
    }
    // Control characters would survive HTML-escaping and come out as invisible
    // damage to the summary line.
    if folder.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "a folder name may not contain control characters",
        ));
    }
    Ok(Some(folder.to_string()))
}

/// Remove a resource. Only its owner can, and only their own.
///
/// A resource that is not yours is 404 rather than 403, as everywhere else here:
/// a 403 would confirm the id exists.
async fn delete_resource(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let owner = require_account(&state, &headers)?;
    check_rate(&state, owner, RateClass::Mutation)?;
    let resource = ResourceId::from_str(&id).map_err(|_| ApiError::not_found())?;

    let db = state.db.lock().unwrap();
    if !db
        .delete_resource(owner, resource)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_resources(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let owner = require_account(&state, &headers)?;
    let db = state.db.lock().unwrap();
    let resources = db.resources_owned_by(owner).map_err(ApiError::internal)?;
    let resources = resources
        .iter()
        .map(|resource| {
            let shares = db
                .share_recipients(resource.id)
                .map_err(ApiError::internal)?;
            let shared_with = shares
                .iter()
                .filter(|share| share.status == ShareStatus::Accepted)
                .map(|share| share.handle.clone())
                .collect::<Vec<_>>();
            Ok(serde_json::json!({
                "resource_id": resource.id.to_string(),
                "name": resource.name,
                "kind": resource.kind.as_str(),
                "visibility": resource.visibility.as_str(),
                "url": resource.url,
                "folder": resource.folder,
                "shared_with": shared_with,
                "shares": shares.iter().map(|share| serde_json::json!({
                    "handle": share.handle,
                    "status": share.status.as_str(),
                })).collect::<Vec<_>>(),
            }))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(serde_json::json!({
        "resources": resources
    })))
}

async fn set_resource_shares(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SetSharesRequest>,
) -> ApiResult<impl IntoResponse> {
    let owner = require_account(&state, &headers)?;
    check_rate(&state, owner, RateClass::Mutation)?;
    let resource_id = ResourceId::from_str(&id).map_err(|_| ApiError::not_found())?;

    let mut db = state.db.lock().unwrap();
    let resource = db
        .resource(resource_id)
        .map_err(ApiError::internal)?
        .filter(|resource| resource.owner_id == owner)
        .ok_or_else(ApiError::not_found)?;
    if resource.visibility != Visibility::Shared && !body.share_with.is_empty() {
        return Err(ApiError::bad_request(
            "only a shared resource can name viewers",
        ));
    }
    let viewers = resolve_share_accounts(&db, owner, &body.share_with)?;
    db.set_shares(resource_id, &viewers)
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_share_invitations(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let viewer = require_browser_account(&state, &headers)?;
    let db = state.db.lock().unwrap();
    let invitations = db.incoming_shares(viewer).map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "shares": invitations.iter().map(|invitation| serde_json::json!({
            "resource_id": invitation.resource.id.to_string(),
            "name": invitation.resource.name,
            "kind": invitation.resource.kind.as_str(),
            "url": invitation.resource.url,
            "owner_handle": invitation.owner_handle,
            "status": invitation.status.as_str(),
        })).collect::<Vec<_>>()
    })))
}

async fn accept_share_invitation(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let viewer = require_browser_account(&state, &headers)?;
    check_rate(&state, viewer, RateClass::Mutation)?;
    let resource = ResourceId::from_str(&id).map_err(|_| ApiError::not_found())?;
    let mut db = state.db.lock().unwrap();
    if !db
        .accept_share(viewer, resource)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn decline_share_invitation(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let viewer = require_browser_account(&state, &headers)?;
    check_rate(&state, viewer, RateClass::Mutation)?;
    let resource = ResourceId::from_str(&id).map_err(|_| ApiError::not_found())?;
    let mut db = state.db.lock().unwrap();
    if !db
        .decline_share(viewer, resource)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
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
    let machine = require_machine(&state, &headers)?;
    check_rate(&state, machine.account.id, RateClass::Mutation)?;
    verify_endpoint_proof(&machine.endpoint_id, &body.proof)?;

    let db = state.db.lock().unwrap();
    db.register_daemon(machine.account.id, &machine.endpoint_id)
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Report endpoint identities without implying daemon liveness. Registration is
/// durable and records only which endpoint the account currently addresses.
async fn daemon_info(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let machine = require_machine(&state, &headers)?;
    let registered_endpoint_id = state
        .db
        .lock()
        .unwrap()
        .daemon_endpoint(machine.account.id)
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "credential_endpoint_id": machine.endpoint_id,
        "registration_matches_credential": registered_endpoint_id.as_deref()
            == Some(machine.endpoint_id.as_str()),
        "registered_endpoint_id": registered_endpoint_id,
    })))
}

async fn daemon_authorizations(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let machine = require_machine(&state, &headers)?;
    let pairs = state
        .db
        .lock()
        .unwrap()
        .service_authorizations(machine.account.id)
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "authorizations": pairs.into_iter().map(|(viewer, resource)| serde_json::json!({
            "viewer_id": viewer.to_string(),
            "resource_id": resource.to_string(),
        })).collect::<Vec<_>>()
    })))
}

/// Consume a one-use browser ticket, bind it to the daemon's Ed25519 identity,
/// and rotate it into the persistent machine credential stored by the CLI.
async fn enroll_machine(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<EnrollMachineRequest>,
) -> ApiResult<impl IntoResponse> {
    let ticket = bearer_token(&headers).ok_or_else(ApiError::unauthorized)?;
    if !valid_prefixed_token(&ticket, "dmt_") {
        return Err(ApiError::unauthorized());
    }
    verify_endpoint_proof(&body.endpoint_id, &body.proof)?;

    let now = now_secs();
    let ticket_hash = auth::hash_token(&ticket);
    let token = auth::generate_machine_token();
    let token_hash = auth::hash_token(&token);
    let (credential_id, account) = {
        state
            .db
            .lock()
            .unwrap()
            .machine_enrollment(&ticket_hash)
            .map_err(ApiError::internal)?
            .ok_or_else(ApiError::unauthorized)?
    };
    check_rate(&state, account, RateClass::Credential)?;
    if !state
        .db
        .lock()
        .unwrap()
        .enroll_machine(
            &credential_id,
            account,
            &ticket_hash,
            &token_hash,
            &body.endpoint_id,
            now,
        )
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unauthorized());
    }

    Ok(Json(serde_json::json!({
        "machine_credential": token,
        "endpoint_id": body.endpoint_id,
    })))
}

fn verify_endpoint_proof(endpoint_id: &str, proof: &str) -> ApiResult<()> {
    let endpoint = parse_endpoint_id(endpoint_id)
        .ok_or_else(|| ApiError::bad_request("endpoint_id is not a 32 byte Ed25519 key"))?;
    let signature = data_encoding::BASE64URL_NOPAD
        .decode(proof.as_bytes())
        .map_err(|_| ApiError::bad_request("endpoint proof is not base64url"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| ApiError::bad_request("endpoint proof is not a 64 byte signature"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&endpoint)
        .map_err(|_| ApiError::bad_request("endpoint_id is not a valid Ed25519 key"))?;
    use ed25519_dalek::Verifier;
    key.verify(
        &devsite_proto::machine_endpoint_proof_message(&endpoint),
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| ApiError::bad_request("endpoint proof did not verify"))
}

// -- dashboard ---------------------------------------------------------------

async fn profile_settings(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let account = require_browser_account(&state, &headers)?;
    let db = state.db.lock().unwrap();
    let private_only = db
        .profile_private_only(account)
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({ "private_only": private_only })))
}

async fn set_profile_settings(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ProfileSettingsRequest>,
) -> ApiResult<impl IntoResponse> {
    let account = require_browser_account(&state, &headers)?;
    check_rate(&state, account, RateClass::Mutation)?;
    let db = state.db.lock().unwrap();
    db.set_profile_private_only(account, body.private_only)
        .map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::json!({ "private_only": body.private_only }),
    ))
}

const MAX_MACHINE_CREDENTIALS: usize = 10;
const MAX_MACHINE_NAME: usize = 60;

fn validate_machine_name(name: &str) -> ApiResult<&str> {
    if name.trim() != name || name.is_empty() {
        return Err(ApiError::bad_request("a machine name may not be blank"));
    }
    if name.chars().count() > MAX_MACHINE_NAME {
        return Err(ApiError::bad_request(format!(
            "a machine name may be at most {MAX_MACHINE_NAME} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "a machine name may not contain control characters",
        ));
    }
    Ok(name)
}

async fn list_machine_credentials(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let account = require_browser_account(&state, &headers)?;
    let db = state.db.lock().unwrap();
    let credentials = db
        .machine_credentials(account)
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "credentials": credentials.iter().map(|credential| serde_json::json!({
            "id": credential.id,
            "name": credential.name,
            "created_at": credential.created_at,
            "last_used_at": credential.last_used_at,
            "endpoint_id": credential.endpoint_id,
            "enrolled_at": credential.enrolled_at,
        })).collect::<Vec<_>>()
    })))
}

async fn create_machine_credential(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<CreateMachineCredentialRequest>,
) -> ApiResult<impl IntoResponse> {
    let account = require_browser_account(&state, &headers)?;
    check_rate(&state, account, RateClass::Credential)?;
    let name = validate_machine_name(&body.name)?;
    let ticket = auth::generate_machine_ticket();
    let id = auth::generate_machine_credential_id();
    let now = now_secs();

    let db = state.db.lock().unwrap();
    if db
        .active_machine_credential_count(account)
        .map_err(ApiError::internal)?
        >= MAX_MACHINE_CREDENTIALS
    {
        return Err(ApiError::bad_request(format!(
            "an account may have at most {MAX_MACHINE_CREDENTIALS} active machine credentials"
        )));
    }
    db.create_machine_credential(&id, account, name, &auth::hash_token(&ticket), now)
        .map_err(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "credential": {
                "id": id,
                "name": name,
                "created_at": now,
                "last_used_at": null,
            },
            "ticket": ticket,
        })),
    ))
}

async fn revoke_machine_credential(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let account = require_browser_account(&state, &headers)?;
    check_rate(&state, account, RateClass::Credential)?;
    let db = state.db.lock().unwrap();
    if !db
        .revoke_machine_credential(account, &id, now_secs())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

// -- themes --------------------------------------------------------------------

/// The presentation properties a profile may set, and what each one accepts.
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

async fn read_theme(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
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
    check_rate(&state, account, RateClass::Mutation)?;
    const MAX_THEME_BYTES: usize = 16 * 1024;
    if body.css.len() > MAX_THEME_BYTES {
        return Err(ApiError::bad_request(format!(
            "a theme may be at most {MAX_THEME_BYTES} bytes"
        )));
    }

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
    if db
        .profile_private_only(owner.id)
        .map_err(ApiError::internal)?
        && viewer != Some(owner.id)
    {
        return Err(ApiError::not_found());
    }

    let mut entries = Vec::new();
    for resource in db
        .resources_owned_by(owner.id)
        .map_err(ApiError::internal)?
    {
        let shared_with = db.shared_with(resource.id).map_err(ApiError::internal)?;
        // The single choke point. A resource that fails here is not merely hidden from the
        // rendering — it never enters the response at all.
        if !can_view(viewer, owner.id, resource.visibility, &shared_with) {
            continue;
        }
        entries.push(to_entry(&resource, None));
    }

    // "Shared with me" belongs on your own profile, not on everyone else's. Listing it on
    // @alice's page would also show Bob the same Agent entry twice.
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

    // No `is_owner`: it existed to decide whether to draw the theme editor, and
    // the website no longer writes anything. What the owner sees that others do
    // not is already expressed by the entries themselves — private resources,
    // and the "shared with me" list, which is populated for the owner alone.
    Ok(Json(ProfileResponse {
        handle,
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
        folder: resource.folder.clone(),
        owner_handle,
    }
}

const CONNECTION_TICKET_LIFETIME_SECS: u64 = 2 * 60;
const TUNNEL_SESSION_LIFETIME_SECS: u64 = 8 * 60 * 60;
const CONNECTION_TICKET_PREFIX: &str = "dst_";
const TUNNEL_SESSION_PREFIX: &str = "dss_";

/// Mint a short-lived, single-use bootstrap ticket from an authenticated browser.
async fn create_connection_ticket(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let viewer = require_browser_account(&state, &headers)?;
    check_rate(&state, viewer, RateClass::Capability)?;
    let resource_id = ResourceId::from_str(&id).map_err(|_| ApiError::not_found())?;
    let now = now_secs();
    let ticket = prefixed_token(CONNECTION_TICKET_PREFIX);
    let expires_at = now + CONNECTION_TICKET_LIFETIME_SECS;

    let db = state.db.lock().unwrap();
    let resource = db
        .resource(resource_id)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;
    let shared_with = db.shared_with(resource_id).map_err(ApiError::internal)?;
    if resource.kind != ResourceKind::Service
        || !can_view(
            Some(viewer),
            resource.owner_id,
            resource.visibility,
            &shared_with,
        )
    {
        return Err(ApiError::not_found());
    }
    db.create_connection_ticket(
        &auth::hash_token(&ticket),
        viewer,
        resource_id,
        now,
        expires_at,
    )
    .map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(ConnectionTicketResponse { ticket, expires_at }),
    ))
}

/// Consume a browser ticket and replace it with a session bound to the CLI's
/// ephemeral Iroh endpoint key. The session should remain in process memory only.
async fn redeem_connection_ticket(
    State(state): State<Shared>,
    Json(body): Json<RedeemTicketRequest>,
) -> ApiResult<impl IntoResponse> {
    if !valid_prefixed_token(&body.ticket, CONNECTION_TICKET_PREFIX) {
        return Err(invalid_ticket());
    }
    let client_key = parse_endpoint_id(&body.client_endpoint_id)
        .ok_or_else(|| ApiError::bad_request("client_endpoint_id is not a 32 byte hex key"))?;
    let client_endpoint_id = data_encoding::HEXLOWER.encode(&client_key);
    let now = now_secs();
    let session_token = prefixed_token(TUNNEL_SESSION_PREFIX);
    let expires_at = now + TUNNEL_SESSION_LIFETIME_SECS;

    let resource = {
        let db = state.db.lock().unwrap();
        let (viewer, resource_id) = db
            .consume_connection_ticket(&auth::hash_token(&body.ticket), now)
            .map_err(ApiError::internal)?
            .ok_or_else(invalid_ticket)?;
        let resource = db
            .resource(resource_id)
            .map_err(ApiError::internal)?
            .ok_or_else(invalid_ticket)?;
        let shared_with = db.shared_with(resource_id).map_err(ApiError::internal)?;
        if resource.kind != ResourceKind::Service
            || !can_view(
                Some(viewer),
                resource.owner_id,
                resource.visibility,
                &shared_with,
            )
        {
            return Err(invalid_ticket());
        }
        db.create_tunnel_session(
            &auth::hash_token(&session_token),
            viewer,
            resource_id,
            &client_endpoint_id,
            now,
            expires_at,
        )
        .map_err(ApiError::internal)?;
        resource
    };

    Ok(Json(RedeemTicketResponse {
        session_token,
        resource_id: resource.id.to_string(),
        name: resource.name,
        expires_at,
    }))
}

/// Issue a fresh, short capability for one local TCP connection.
///
/// Denials are 404 rather than 403 throughout: a 403 would confirm that a resource id
/// exists, which is enough to enumerate someone's private services.
async fn tunnel_capability(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let token = bearer_token(&headers).ok_or_else(invalid_tunnel_session)?;
    if !valid_prefixed_token(&token, TUNNEL_SESSION_PREFIX) {
        return Err(invalid_tunnel_session());
    }
    let now = now_secs();

    let (session, resource, endpoint_id) = {
        let db = state.db.lock().unwrap();
        let session = db
            .tunnel_session(&auth::hash_token(&token), now)
            .map_err(ApiError::internal)?
            .ok_or_else(invalid_tunnel_session)?;
        let resource = db
            .resource(session.resource_id)
            .map_err(ApiError::internal)?
            .ok_or_else(ApiError::not_found)?;
        let shared_with = db
            .shared_with(session.resource_id)
            .map_err(ApiError::internal)?;

        if !can_view(
            Some(session.viewer_id),
            resource.owner_id,
            resource.visibility,
            &shared_with,
        ) {
            tracing::warn!(
                viewer = %session.viewer_id,
                resource = %session.resource_id,
                "refused a capability request"
            );
            return Err(ApiError::not_found());
        }
        if resource.kind != ResourceKind::Service {
            return Err(ApiError::bad_request(
                "that resource is a link, not a service",
            ));
        }
        let endpoint_id = db
            .daemon_endpoint(resource.owner_id)
            .map_err(ApiError::internal)?;
        (session, resource, endpoint_id)
    };
    check_rate(&state, session.viewer_id, RateClass::Capability)?;
    let client_key = parse_endpoint_id(&session.client_endpoint_id).ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("stored client endpoint id is invalid"))
    })?;

    // The only thing that can be answered from here. Whether the daemon is
    // *running* is not knowable at this end without asking it, so the client discovers
    // that when it connects. This case is the narrower one:
    // no daemon has ever registered, so there is not even an address to try.
    let endpoint_id = endpoint_id.ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "no daemon has been registered for that service — run `devsite daemon run`".into(),
        )
    })?;

    let audience = parse_endpoint_id(&endpoint_id).ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("stored daemon endpoint id is invalid"))
    })?;

    let capability = state
        .issuer
        .issue(session.viewer_id, resource.id, audience, client_key, now)
        .map_err(ApiError::internal)?;

    Ok(Json(CapabilityResponse {
        capability: data_encoding::BASE64URL_NOPAD.encode(&capability.to_bytes()),
        daemon_endpoint_id: endpoint_id,
    }))
}

async fn delete_tunnel_session(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let token = bearer_token(&headers).ok_or_else(invalid_tunnel_session)?;
    if !valid_prefixed_token(&token, TUNNEL_SESSION_PREFIX) {
        return Err(invalid_tunnel_session());
    }
    // DELETE is idempotent. A share or resource revocation may already have
    // cascaded the row away while the CLI was still running.
    state
        .db
        .lock()
        .unwrap()
        .delete_tunnel_session(&auth::hash_token(&token))
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

fn prefixed_token(prefix: &str) -> String {
    format!("{prefix}{}", auth::generate_session_token())
}

fn valid_prefixed_token(token: &str, prefix: &str) -> bool {
    token.len() == prefix.len() + 43
        && token.starts_with(prefix)
        && token[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn invalid_ticket() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "invalid or expired ticket".into())
}

fn invalid_tunnel_session() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "invalid or expired tunnel session".into(),
    )
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
    fn links_support_every_visibility_and_tcp_services_are_not_public() {
        assert!(validate_resource_visibility(ResourceKind::Link, Visibility::Public).is_ok());
        assert!(validate_resource_visibility(ResourceKind::Link, Visibility::Private).is_ok());
        assert!(validate_resource_visibility(ResourceKind::Link, Visibility::Shared).is_ok());
        assert!(validate_resource_visibility(ResourceKind::Service, Visibility::Private).is_ok());
        assert!(validate_resource_visibility(ResourceKind::Service, Visibility::Shared).is_ok());
        assert!(validate_resource_visibility(ResourceKind::Service, Visibility::Public).is_err());
    }

    #[test]
    fn parses_a_valid_endpoint_id() {
        let hex = "89ef8f68b58d5dbfa8501010a0f2ea3afaf80952f04e6767fadbf6d16658e7a0";
        assert!(parse_endpoint_id(hex).is_some());
        assert!(parse_endpoint_id(&hex.to_uppercase()).is_some());
    }

    #[test]
    fn rejects_endpoint_ids_of_the_wrong_shape() {
        for bad in [
            "",
            "abcd",
            "zz",
            "89ef8f68b58d5dbfa8501010a0f2ea3afaf80952f04e6767fadbf6d16658e7",
        ] {
            assert!(
                parse_endpoint_id(bad).is_none(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn endpoint_proof_requires_the_matching_private_key() {
        use ed25519_dalek::{Signer, SigningKey};

        let key = SigningKey::from_bytes(&[7; 32]);
        let endpoint = key.verifying_key().to_bytes();
        let endpoint_id = data_encoding::HEXLOWER.encode(&endpoint);
        let signature = key.sign(&devsite_proto::machine_endpoint_proof_message(&endpoint));
        let proof = data_encoding::BASE64URL_NOPAD.encode(&signature.to_bytes());
        assert!(verify_endpoint_proof(&endpoint_id, &proof).is_ok());

        let attacker = SigningKey::from_bytes(&[8; 32]);
        let forged = attacker.sign(&devsite_proto::machine_endpoint_proof_message(&endpoint));
        let forged = data_encoding::BASE64URL_NOPAD.encode(&forged.to_bytes());
        assert!(verify_endpoint_proof(&endpoint_id, &forged).is_err());
    }

    #[test]
    fn bootstrap_and_session_tokens_have_distinct_bounded_shapes() {
        let ticket = prefixed_token(CONNECTION_TICKET_PREFIX);
        let session = prefixed_token(TUNNEL_SESSION_PREFIX);
        assert!(valid_prefixed_token(&ticket, CONNECTION_TICKET_PREFIX));
        assert!(valid_prefixed_token(&session, TUNNEL_SESSION_PREFIX));
        assert!(!valid_prefixed_token(&ticket, TUNNEL_SESSION_PREFIX));
        assert!(!valid_prefixed_token(
            &format!("{ticket}extra"),
            CONNECTION_TICKET_PREFIX
        ));
        assert!(!valid_prefixed_token(
            "dst_not/base64url________________________________",
            CONNECTION_TICKET_PREFIX
        ));
    }

    #[test]
    fn blank_folder_names_are_the_same_as_none() {
        // Otherwise a profile grows a fold with no label that nothing can remove,
        // because the only way to remove a folder is to stop naming it.
        for blank in [Some(""), Some("   "), Some("\t"), None] {
            assert_eq!(validate_folder(blank).unwrap(), None, "{blank:?}");
        }
        assert_eq!(
            validate_folder(Some("  Games ")).unwrap().as_deref(),
            Some("Games")
        );
    }

    #[test]
    fn folder_names_are_bounded_and_printable() {
        assert!(validate_folder(Some(&"x".repeat(theme::MAX_FOLDER_NAME))).is_ok());
        assert!(validate_folder(Some(&"x".repeat(theme::MAX_FOLDER_NAME + 1))).is_err());
        assert!(validate_folder(Some("Games\u{0}")).is_err());
        assert!(validate_folder(Some("two\nlines")).is_err());
    }

    #[test]
    fn resource_names_are_bounded_and_printable() {
        assert_eq!(validate_resource_name("Agent").unwrap(), "Agent");
        for bad in ["", " Agent", "Agent ", "two\nlines"] {
            assert!(
                validate_resource_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(validate_resource_name(&"x".repeat(MAX_RESOURCE_NAME)).is_ok());
        assert!(validate_resource_name(&"x".repeat(MAX_RESOURCE_NAME + 1)).is_err());
    }

    #[test]
    fn public_links_are_http_urls_without_embedded_credentials() {
        assert_eq!(
            validate_public_url("https://example.com/path").unwrap(),
            "https://example.com/path"
        );
        for bad in [
            "javascript:alert(1)",
            "data:text/html,hi",
            "/relative",
            "https://user:secret@example.com/",
            "not a url",
        ] {
            assert!(
                validate_public_url(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rate_limits_reset_after_the_window() {
        let account = AccountId::from_bytes([9; 16]);
        let mut limits = RateLimits::default();
        for _ in 0..RateClass::Session.limit() {
            assert!(limits.check(account, RateClass::Session, 100));
        }
        assert!(!limits.check(account, RateClass::Session, 100));
        assert!(limits.check(account, RateClass::Session, 160));
    }

    #[test]
    fn reads_the_session_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=dark; devsite_session=abc123; other=x"
                .parse()
                .unwrap(),
        );
        assert_eq!(cookie_token(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn prefers_an_explicit_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer cli-token".parse().unwrap());
        assert_eq!(bearer_token(&headers).as_deref(), Some("cli-token"));
    }

    #[test]
    fn planning_a_resource_validates_without_writing() {
        let db = Db::open(":memory:").unwrap();
        let alice = db.upsert_account("test", "alice", 1).unwrap();
        let body = CreateResourceRequest {
            name: "docs".into(),
            kind: "link".into(),
            visibility: "public".into(),
            url: Some("https://example.com/docs".into()),
            share_with: Vec::new(),
            folder: Some("Projects".into()),
        };

        let prepared = prepare_resource(&db, alice.id, &body).unwrap();

        assert_eq!(prepared.plan.operation, "create");
        assert_eq!(db.resource_count(alice.id).unwrap(), 0);
        assert_eq!(prepared.plan.target.resource_id, None);
    }

    #[test]
    fn changing_a_shared_link_destination_plans_reapproval() {
        let mut db = Db::open(":memory:").unwrap();
        let alice = db.upsert_account("test", "alice", 1).unwrap();
        let bob = db.upsert_account("test", "bob", 1).unwrap();
        db.set_handle(bob.id, "bob").unwrap();
        let resource = db
            .create_resource(
                alice.id,
                "staging",
                ResourceKind::Link,
                Visibility::Shared,
                Some("https://old.example.com/"),
                None,
                1,
            )
            .unwrap();
        db.set_shares(resource, &[bob.id]).unwrap();
        assert!(db.accept_share(bob.id, resource).unwrap());
        let body = CreateResourceRequest {
            name: "staging".into(),
            kind: "link".into(),
            visibility: "shared".into(),
            url: Some("https://new.example.com/".into()),
            share_with: vec!["bob".into()],
            folder: None,
        };

        let prepared = prepare_resource(&db, alice.id, &body).unwrap();

        assert_eq!(prepared.plan.operation, "update");
        assert!(prepared.plan.recipient_changes.iter().any(|change| {
            change.handle == "bob"
                && change.from == Some("accepted")
                && change.to == Some("pending")
                && change.reason == "destination_changed"
        }));
        assert!(prepared.plan.effects.iter().any(|effect| {
            effect.code == "recipient_reapproval_required" && effect.handles == ["bob"]
        }));
        assert_eq!(
            db.share_recipients(resource).unwrap()[0].status,
            ShareStatus::Accepted,
            "planning must not mutate recipient state"
        );
    }
}
