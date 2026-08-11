//! The dev.site control plane.
//!
//! Holds identities, profiles, permissions and daemon presence, and issues short-lived
//! capabilities. It never carries private service traffic.

mod api;
mod auth;
mod db;
mod issuer;
mod policy;
mod theme;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::http::{header, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::api::AppState;
use crate::auth::ShooVerifier;
use crate::db::Db;
use crate::issuer::Issuer;

struct Config {
    bind: String,
    /// The exact origin browsers load, e.g. `https://dev.site`. Shoo derives its client id
    /// and pairwise subjects from this, so changing it changes every account identity.
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
            signing_key: std::env::var("DEVSITE_SIGNING_KEY").ok().filter(|k| !k.trim().is_empty()),
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
        let handle = args.get(1).context("usage: devsite-server issue-session <handle>")?;
        return issue_session(&config, handle);
    }

    let db = Db::open(&config.database)?;
    let issuer = config.issuer()?;
    let shoo = ShooVerifier::new(&config.public_origin);

    tracing::info!(
        origin = %config.public_origin,
        audience = %shoo.audience(),
        "capability signing key {}",
        issuer.public_key_hex()
    );

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        issuer,
        shoo,
        public_origin: config.public_origin.clone(),
    });

    let index = config.web_root.join("index.html");
    let app = api::router(Arc::clone(&state))
        // Nothing from the API is ever cacheable: profiles depend on who is asking, and a
        // cached capability would be a reusable grant sitting in a shared cache.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, private"),
        ))
        // `/@handle` and `/auth/callback` are client-side routes; serve the shell and let
        // the page work out what to render.
        .route("/@{handle}", get(serve_index(index.clone())))
        .route("/auth/callback", get(serve_index(index.clone())))
        .fallback_service(static_assets(&config.web_root, &index))
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

/// Static assets, with a cache policy that matches how they are versioned.
///
/// `/pkg/<hash>/*` is content-addressed by `scripts/build-wasm.sh`, so it can be cached
/// forever — a new build lands on a new path. Everything else, including the manifest that
/// names the current hash, must revalidate, or a deploy would leave browsers pinned to the
/// previous bundle.
fn static_assets(web_root: &std::path::Path, index: &std::path::Path) -> axum::routing::Router {
    let files = ServeDir::new(web_root).not_found_service(ServeFile::new(index));

    axum::routing::Router::new()
        .fallback_service(files)
        .layer(axum::middleware::from_fn(|req: axum::extract::Request, next: axum::middleware::Next| async move {
            let path = req.uri().path().to_string();
            let mut response = next.run(req).await;
            let policy = if path.starts_with("/pkg/") && !path.ends_with("manifest.json") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static(policy));
            response
        }))
}

/// Serve the SPA shell for client-side routes.
///
/// Read per request rather than cached so editing the page during development does not
/// need a server restart.
fn serve_index(path: PathBuf) -> impl Fn() -> std::future::Ready<Response> + Clone {
    move || {
        let body = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            "<!doctype html><p>web/index.html is missing.".to_string()
        });
        std::future::ready(Html(body).into_response())
    }
}

/// Mint a session for `handle`, creating the account if it does not exist.
///
/// The account is keyed on a `local:` subject so it can never collide with a Shoo pairwise
/// subject — signing in through Shoo will always produce a separate account rather than
/// silently adopting one made here.
fn issue_session(config: &Config, handle: &str) -> Result<()> {
    let db = Db::open(&config.database)?;
    let handle = crate::auth::validate_handle(handle)?;
    let now = api::now_secs();

    // Attach to the existing account when the handle is taken. Creating a second one would
    // collide on the unique handle, and the useful operator action here is "give me a
    // session for @dami" — including when @dami signed in through Shoo.
    let account = match db.account_by_handle(&handle)? {
        Some(existing) => existing,
        None => {
            let created = db.upsert_account(&format!("local:{handle}"), now)?;
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
