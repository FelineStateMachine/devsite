//! The viewer side of the dev.site data plane.
//!
//! This crate compiles for both native and `wasm32-unknown-unknown`. The browser runs it
//! through `devsite-web`; the integration tests run it natively. Keeping one
//! implementation means the authorization behaviour proven by fast native tests is
//! literally the same code the browser executes.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use devsite_proto::capability::SignedCapability;
use devsite_proto::wire::{self, ErrorCode, HttpRequest, Method, Request, Response};
use devsite_proto::ALPN;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::time::timeout;

/// How long to wait for a daemon before giving up on it.
///
/// There is no presence service telling us in advance whether the far end is
/// running, so this is what "offline" means now: we asked, and nobody answered.
/// Long enough to cover address lookup and a relay handshake, short enough that
/// a dead daemon does not leave someone watching a spinner.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Why a fetch did not produce a page.
///
/// Transport failure and refusal are kept distinct so a caller — and especially a test —
/// can tell "the daemon said no" from "we never reached the daemon". Collapsing the two
/// would let a network timeout masquerade as a successful authorization check.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The daemon reached a verdict and refused.
    #[error("the daemon denied this request")]
    Denied,
    /// The daemon responded, but with some other refusal.
    #[error("the daemon rejected this request ({0:?})")]
    Rejected(ErrorCode),
    /// We never got a verdict: connection, relay, or protocol failure.
    #[error(transparent)]
    Transport(#[from] anyhow::Error),
}

impl From<wire::CodecError> for FetchError {
    fn from(err: wire::CodecError) -> Self {
        FetchError::Transport(err.into())
    }
}

/// A page fetched from a remote daemon.
#[derive(Debug, Clone)]
pub struct FetchedPage {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl FetchedPage {
    /// The body as text. Used to hand HTML to a sandboxed iframe.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A viewer endpoint. In the browser this is ephemeral — a fresh key per tab session — so
/// a capability issued for it dies with the page.
pub struct ViewerEndpoint {
    endpoint: Endpoint,
    /// One live connection per daemon, reused across requests.
    ///
    /// Connecting per request does not work: dropping a `Connection` closes it, and the
    /// endpoint hands the same closed connection back to the next `connect` for that peer,
    /// which then fails with "closed". Holding it open is also simply what a browsing
    /// session wants — several pages from one daemon over one relay connection.
    connections: Mutex<HashMap<EndpointId, Connection>>,
}

impl ViewerEndpoint {
    /// Bind a new endpoint with a freshly generated key and wait until a relay has
    /// accepted us. Browsers have no direct UDP path, so the relay is the only way out.
    pub async fn create() -> Result<Self> {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .context("binding viewer endpoint")?;
        endpoint.online().await;
        Ok(Self {
            endpoint,
            connections: Mutex::new(HashMap::new()),
        })
    }

    /// This viewer's public key. The control plane binds capabilities to it, and the
    /// daemon checks that binding against the authenticated peer of the connection.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Fetch a page from a daemon, presenting `capability`.
    ///
    /// `daemon` is normally a bare [`EndpointId`]: the daemon publishes its own
    /// address through iroh's address lookup, and the browser resolves it over
    /// HTTPS. Nothing has to tell us where it is. Callers that already know an
    /// address — the tests, which want a relay pinned rather than a lookup — can
    /// pass a fuller [`EndpointAddr`].
    ///
    /// The capability must have been issued for this endpoint's key; the daemon checks
    /// that binding against the connection and will refuse otherwise.
    pub async fn fetch(
        &self,
        daemon: impl Into<EndpointAddr>,
        capability: SignedCapability,
        path: &str,
    ) -> Result<FetchedPage, FetchError> {
        let addr = daemon.into();
        let connection = self.connection_to(&addr).await?;
        match request_page(&connection, capability.clone(), path).await {
            Err(FetchError::Transport(err)) => {
                // The cached connection may simply have aged out. Drop it and try once
                // more on a fresh one before reporting failure.
                tracing::debug!("retrying on a fresh connection: {err:#}");
                self.connections.lock().unwrap().remove(&addr.id);
                let connection = self.connection_to(&addr).await?;
                request_page(&connection, capability, path).await
            }
            other => other,
        }
    }

    /// A live connection to `daemon`, reusing the cached one when there is one.
    async fn connection_to(&self, daemon: &EndpointAddr) -> Result<Connection, FetchError> {
        // Scoped so the guard is released before the await below. An `if let` scrutinee
        // temporary would otherwise live to the end of the whole statement, and the
        // second lock in this function would deadlock against it.
        let existing = {
            let cache = self.connections.lock().unwrap();
            cache.get(&daemon.id).cloned()
        };
        if let Some(existing) = existing {
            return Ok(existing);
        }
        // Bounded explicitly. Without a presence service there is nothing to tell
        // us the far end is down before we try, so an unreachable daemon has to
        // surface as a timeout rather than as a connect that waits on the relay.
        let connection = timeout(CONNECT_TIMEOUT, self.endpoint.connect(daemon.clone(), ALPN))
            .await
            .map_err(|_| anyhow::anyhow!("no answer from the daemon"))?
            .context("connecting to daemon")?;
        self.connections
            .lock()
            .unwrap()
            .insert(daemon.id, connection.clone());
        Ok(connection)
    }
}

async fn request_page(
    connection: &Connection,
    capability: SignedCapability,
    path: &str,
) -> Result<FetchedPage, FetchError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("opening bidirectional stream")?;

    let request = Request::Http(HttpRequest {
        capability,
        method: Method::Get,
        path: path.to_string(),
    });
    send.write_all(&wire::encode(&request)?)
        .await
        .context("writing request frame")?;
    send.finish().context("finishing request stream")?;

    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .context("reading response length")?;
    let len = wire::frame_len(prefix)?;
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .context("reading response frame")?;

    let response = wire::decode::<Response>(&payload).context("decoding response frame")?;
    match response {
        Response::Http {
            status,
            content_type,
            body,
        } => Ok(FetchedPage {
            status,
            content_type,
            body,
        }),
        Response::Error {
            code: ErrorCode::Denied,
            ..
        } => Err(FetchError::Denied),
        Response::Error { code, .. } => Err(FetchError::Rejected(code)),
    }
}
