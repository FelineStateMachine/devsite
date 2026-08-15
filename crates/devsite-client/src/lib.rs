//! The connecting-client side of the dev.site data plane.
//!
//! Each accepted local TCP connection becomes one authenticated Iroh bidirectional stream.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use devsite_proto::capability::SignedCapability;
use devsite_proto::wire::{self, ConnectRequest, ErrorCode, Request, Response};
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

/// Why a service stream could not be opened.
///
/// Transport failure and refusal are kept distinct so a caller — and especially a test —
/// can tell "the daemon said no" from "we never reached the daemon". Collapsing the two
/// would let a network timeout masquerade as a successful authorization check.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
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

impl From<wire::CodecError> for ConnectError {
    fn from(err: wire::CodecError) -> Self {
        ConnectError::Transport(err.into())
    }
}

/// The two halves of an authorized service byte stream.
pub struct ServiceStream {
    pub send: iroh::endpoint::SendStream,
    pub recv: iroh::endpoint::RecvStream,
}

/// An ephemeral client endpoint. A capability is bound to this key and therefore cannot
/// be redeemed by another devsite client.
pub struct ClientEndpoint {
    endpoint: Endpoint,
    /// One live connection per daemon, reused across service streams.
    ///
    /// Connecting per request does not work: dropping a `Connection` closes it, and the
    /// endpoint hands the same closed connection back to the next connection for that peer,
    /// which then fails with "closed". Holding it open also lets many local connections
    /// share one authenticated QUIC connection.
    connections: Mutex<HashMap<EndpointId, Connection>>,
}

impl ClientEndpoint {
    /// Bind a new endpoint with a freshly generated key and wait until it is online.
    pub async fn create() -> Result<Self> {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .context("binding client endpoint")?;
        endpoint.online().await;
        Ok(Self {
            endpoint,
            connections: Mutex::new(HashMap::new()),
        })
    }

    /// Bind an endpoint with a caller-provided key. Brokered grants use this so
    /// the endpoint that signed the request is also the endpoint that connects.
    pub async fn create_with_secret(secret_key: iroh::SecretKey) -> Result<Self> {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .bind()
            .await
            .context("binding client endpoint")?;
        endpoint.online().await;
        Ok(Self {
            endpoint,
            connections: Mutex::new(HashMap::new()),
        })
    }

    /// Bind an endpoint with relay settings from the control plane.
    pub async fn create_with_relay(
        secret_key: iroh::SecretKey,
        relay_access: devsite_iroh::RelayAccess,
    ) -> Result<Self> {
        let endpoint = Endpoint::builder(devsite_iroh::preset(secret_key, relay_access)?)
            .bind()
            .await
            .context("binding client endpoint")?;
        endpoint.online().await;
        Ok(Self {
            endpoint,
            connections: Mutex::new(HashMap::new()),
        })
    }

    /// This client's public key. The control plane binds capabilities to it, and the
    /// daemon checks that binding against the authenticated peer of the connection.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Close the ephemeral endpoint and every cached daemon connection cleanly.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    /// Open one authorized byte stream to a service behind a daemon.
    ///
    /// `daemon` is normally a bare [`EndpointId`]: the daemon publishes its own
    /// address through iroh's address lookup, and the client resolves it. Nothing has to
    /// tell us where it is. Callers that already know an
    /// address — such as tests that avoid address lookup — can pass a fuller
    /// [`EndpointAddr`].
    ///
    /// The capability must have been issued for this endpoint's key; the daemon checks
    /// that binding against the connection and will refuse otherwise.
    pub async fn connect(
        &self,
        daemon: impl Into<EndpointAddr>,
        capability: SignedCapability,
    ) -> Result<ServiceStream, ConnectError> {
        let addr = daemon.into();
        let connection = self.connection_to(&addr).await?;
        request_stream(&connection, capability).await
    }

    /// A live connection to `daemon`, reusing the cached one when there is one.
    async fn connection_to(&self, daemon: &EndpointAddr) -> Result<Connection, ConnectError> {
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

async fn request_stream(
    connection: &Connection,
    capability: SignedCapability,
) -> Result<ServiceStream, ConnectError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("opening bidirectional stream")?;

    let request = Request::Connect(ConnectRequest { capability });
    send.write_all(&wire::encode(&request)?)
        .await
        .context("writing connect frame")?;

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
        Response::Connected => Ok(ServiceStream { send, recv }),
        Response::Error {
            code: ErrorCode::Denied,
            ..
        } => Err(ConnectError::Denied),
        Response::Error { code, .. } => Err(ConnectError::Rejected(code)),
    }
}
