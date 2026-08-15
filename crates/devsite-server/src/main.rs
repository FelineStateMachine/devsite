//! The dev.site control plane.
//!
//! Holds identities, profiles, permissions and daemon presence, and issues short-lived
//! capabilities. It never carries private service traffic.

mod api;
mod auth;
mod db;
mod issuer;
mod oidc;
mod policy;
mod theme;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::http::{header, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::api::{AppState, RateLimits};
use crate::db::Db;
use crate::issuer::Issuer;
use crate::oidc::OidcConfig;

struct Config {
    bind: String,
    /// The exact origin browsers load, e.g. `https://dev.site`. It forms OAuth callback
    /// URLs and the capability issuer name, so it must match the externally visible site.
    public_origin: String,
    database: String,
    state_dir: PathBuf,
    web_root: PathBuf,
    /// The capability signing key as 64 hex characters, when it is supplied
    /// directly rather than kept in `state_dir`. See `Issuer::from_hex`.
    signing_key: Option<String>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let public_origin = std::env::var("DEVSITE_PUBLIC_ORIGIN")
            .context("DEVSITE_PUBLIC_ORIGIN must be set, e.g. https://dev.site")?
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            bind: std::env::var("DEVSITE_BIND").unwrap_or_else(|_| "127.0.0.1:4000".to_string()),
            public_origin,
            database: std::env::var("DEVSITE_DB").unwrap_or_else(|_| "devsite.db".to_string()),
            state_dir: std::env::var("DEVSITE_STATE_DIR")
                .unwrap_or_else(|_| ".devsite-state".to_string())
                .into(),
            web_root: std::env::var("DEVSITE_WEB_ROOT")
                .unwrap_or_else(|_| "web".to_string())
                .into(),
            signing_key: std::env::var("DEVSITE_SIGNING_KEY")
                .ok()
                .filter(|k| !k.trim().is_empty()),
        })
    }

    /// The capability issuer this configuration asks for.
    ///
    /// A supplied key wins over the state directory, and a bad one is fatal
    /// rather than something to fall back from — see `Issuer::from_hex`.
    fn issuer(&self) -> Result<Issuer> {
        match &self.signing_key {
            Some(hex) => {
                tracing::info!("capability signing key supplied by DEVSITE_SIGNING_KEY");
                Issuer::from_hex(hex, &self.public_origin)
            }
            None => Issuer::load_or_create(&self.state_dir, &self.public_origin),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "devsite_server=info,tower_http=warn,warn".into()),
        )
        .init();

    let config = Config::from_env()?;

    // Operator command, deliberately not reachable over HTTP: minting a session requires
    // shell access to the machine holding the database. Used to bootstrap an account (and
    // to exercise the stack without a round trip through Google).
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("issue-session") {
        let handle = args
            .get(1)
            .context("usage: devsite-server issue-session <handle>")?;
        return issue_session(&config, handle);
    }

    let db = Db::open(&config.database)?;
    let issuer = config.issuer()?;
    let relay_config = devsite_iroh::RelayConfig::from_env()?;
    let oidc = OidcConfig::from_env(&config.public_origin)?;

    tracing::info!(
        origin = %config.public_origin,
        identity_namespace = %oidc.issuer(),
        oidc_client_id = %oidc.client_id(),
        "capability signing key {}",
        issuer.public_key_hex()
    );

    let (profile_changes, _) = tokio::sync::broadcast::channel(64);
    let state = Arc::new(AppState {
        db: Mutex::new(db),
        rate_limits: Mutex::new(RateLimits::default()),
        issuer,
        identity_namespace: oidc.issuer().to_string(),
        public_origin: config.public_origin.clone(),
        relay_config,
        profile_changes,
        profile_revision: std::sync::atomic::AtomicU64::new(0),
    });

    let index = config.web_root.join("index.html");
    let app = api::router(Arc::clone(&state))
        .merge(oidc::router(Arc::clone(&state), oidc)?)
        // Nothing from the API is ever cacheable: profiles depend on who is asking, and a
        // cached capability would be a reusable grant sitting in a shared cache.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, private"),
        ))
        // `/@handle` is a client-side route; serve the shell and let the page render it.
        .route("/@{handle}", get(serve_index(index.clone())))
        .fallback_service(static_assets(&config.web_root, &index))
        // Fly also compresses at its edge today, but the origin should have the same
        // contract when it is run directly or moved behind a different proxy.
        .layer(CompressionLayer::new().br(true).gzip(true))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    tracing::info!("listening on http://{}", config.bind);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// Static assets always revalidate. They are small and deployed with the server binary.
fn static_assets(web_root: &std::path::Path, index: &std::path::Path) -> axum::routing::Router {
    let files = ServeDir::new(web_root).not_found_service(ServeFile::new(index));

    axum::routing::Router::new()
        .fallback_service(files)
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(req).await;
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
                response
            },
        ))
}

/// Serve the SPA shell for client-side routes.
///
/// Read per request rather than cached so editing the page during development does not
/// need a server restart.
///
/// The `no-cache` is load-bearing and has to be set here rather than by a layer.
/// `Router::layer` only wraps routes registered before it, so these two sit
/// between the API's `no-store` layer and the static fallback's own headers, and
/// inherit neither. A shell with no directives and no validator is one a browser
/// may cache heuristically. `/` never had the problem; client-side routes silently did.
fn serve_index(path: PathBuf) -> impl Fn() -> std::future::Ready<Response> + Clone {
    move || {
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| "<!doctype html><p>web/index.html is missing.".to_string());
        let mut response = Html(body).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        std::future::ready(response)
    }
}

/// Mint a session for `handle`, creating the account if it does not exist.
///
/// New operator-created accounts use the `local` identity namespace, so they cannot collide
/// with an external provider that happens to issue the same subject.
fn issue_session(config: &Config, handle: &str) -> Result<()> {
    let db = Db::open(&config.database)?;
    let handle = crate::auth::validate_handle(handle)?;
    let now = api::now_secs();

    // Attach to the existing account when the handle is taken. Creating a second one would
    // collide on the unique handle, and the useful operator action here is "give me a
    // session for @alice" — including when @alice signed in through an external provider.
    let account = match db.account_by_handle(&handle)? {
        Some(existing) => existing,
        None => {
            let created = db.upsert_account("local", &handle, now)?;
            db.set_handle(created.id, &handle)?;
            created
        }
    };

    let token = auth::generate_session_token();
    db.create_session(
        &auth::hash_token(&token),
        account.id,
        now + auth::SESSION_LIFETIME_SECS,
    )?;

    println!("account @{handle} ({})", account.id);
    println!("session token:\n{token}");
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spa_shell_is_never_cached_without_revalidating() {
        let index = std::env::temp_dir().join(format!("devsite-index-{}.html", std::process::id()));
        std::fs::write(&index, "<!doctype html><title>x</title>").unwrap();

        let response = serve_index(index.clone())().into_inner();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache",
            "a cached shell pins a browser to assets a later deploy may have removed"
        );

        std::fs::remove_file(&index).ok();
    }
}
