//! The daemon: an Iroh endpoint that proxies *authorized* requests to local services.
//!
//! It has no inbound port. It reaches the world through a relay, and it decides for itself
//! whether to honour a request by verifying a capability signed by the control plane —
//! the control plane never touches this traffic.

pub mod config;
pub mod upstream;
pub mod verify;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use devsite_proto::capability::KeyBytes;
use devsite_proto::wire::{self, ErrorCode, Request, Response};
use devsite_proto::ALPN;
use ed25519_dalek::VerifyingKey;
use iroh::endpoint::Connection;
use iroh::{Endpoint, SecretKey};
use tokio::sync::Mutex;

use crate::config::DaemonConfig;
use crate::verify::{Denied, ReplayGuard};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Daemon {
    endpoint: Endpoint,
    http: reqwest::Client,
    config: DaemonConfig,
    control_plane_key: VerifyingKey,
    replay: Arc<Mutex<ReplayGuard>>,
}

impl Daemon {
    /// Bind the endpoint and wait until a relay will carry traffic for us.
    ///
    /// Fails if no control-plane key has been pinned: a daemon that cannot verify
    /// capabilities must refuse to start rather than run in some permissive mode.
    pub async fn bind(secret_key: SecretKey, config: DaemonConfig) -> Result<Self> {
        let control_plane_key = config.verifying_key()?;

        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .context("binding daemon endpoint")?;
        endpoint.online().await;

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building upstream http client")?;

        Ok(Self {
            endpoint,
            http,
            config,
            control_plane_key,
            replay: Arc::new(Mutex::new(ReplayGuard::default())),
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn endpoint_key(&self) -> KeyBytes {
        *self.endpoint.id().as_bytes()
    }

    /// Accept connections until the endpoint closes.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        tracing::info!(
            resources = self.config.resources.len(),
            "daemon serving; every request must present a valid capability"
        );

        while let Some(incoming) = self.endpoint.accept().await {
            let daemon = Arc::clone(&self);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => daemon.handle_connection(connection).await,
                    Err(err) => tracing::debug!("incoming connection failed: {err:#}"),
                }
            });
        }
        Ok(())
    }

    /// Serve requests until the peer goes away.
    ///
    /// A connection carries many requests, so this loops rather than answering once and
    /// dropping. Closing after a single response leaves the peer holding a dead connection
    /// that its next request reuses — which surfaces as a connect failing with "closed"
    /// rather than as anything obviously wrong here.
    async fn handle_connection(self: Arc<Self>, connection: Connection) {
        // The authenticated peer. This is the only identity we trust about the other side,
        // and the capability's browser binding is checked against it.
        let peer: KeyBytes = *connection.remote_id().as_bytes();

        loop {
            let stream = match connection.accept_bi().await {
                Ok(stream) => stream,
                // The peer closed, or the connection dropped. Either way we are done.
                Err(err) => {
                    tracing::trace!("connection with {} ended: {err}", hex(&peer));
                    return;
                }
            };

            let daemon = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(err) = daemon.handle_stream(stream, &peer).await {
                    tracing::debug!("request from {} failed: {err:#}", hex(&peer));
                }
            });
        }
    }

    async fn handle_stream(
        &self,
        (mut send, mut recv): (iroh::endpoint::SendStream, iroh::endpoint::RecvStream),
        peer: &KeyBytes,
    ) -> Result<()> {
        let mut prefix = [0u8; 4];
        recv.read_exact(&mut prefix)
            .await
            .context("reading request length")?;
        let len = wire::frame_len(prefix)?;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .context("reading request frame")?;

        let response = match wire::decode::<Request>(&payload) {
            Ok(Request::Http(request)) => self.serve_http(request, peer).await,
            Err(err) => {
                tracing::debug!("malformed frame from {}: {err:#}", hex(peer));
                Response::Error {
                    code: ErrorCode::BadRequest,
                    message: "malformed request".to_string(),
                }
            }
        };

        send.write_all(&wire::encode(&response)?)
            .await
            .context("writing response frame")?;
        send.finish().context("finishing response stream")?;
        // Wait for the peer to acknowledge, so the response is not discarded if the
        // connection is torn down immediately after.
        send.stopped().await.ok();
        Ok(())
    }

    async fn serve_http(&self, request: devsite_proto::HttpRequest, peer: &KeyBytes) -> Response {
        let origins = self.config.origins();
        let my_endpoint = self.endpoint_key();
        let now = now_secs();

        let authorized = {
            let mut replay = self.replay.lock().await;
            verify::authorize(
                &request.capability,
                request.method,
                &self.control_plane_key,
                &my_endpoint,
                peer,
                &origins,
                &mut replay,
                now,
            )
        };

        match authorized {
            Ok(authorized) => {
                tracing::info!(
                    viewer = %authorized.claims.viewer,
                    resource = %authorized.claims.resource,
                    path = %request.path,
                    "serving request"
                );
                upstream::fetch(&self.http, &authorized.origin, request.method, &request.path).await
            }
            Err(denied) => {
                // Logged with detail locally, reported to the peer as a bare "denied".
                tracing::warn!(peer = %hex(peer), reason = ?denied, "denied request");
                debug_assert!(matches!(
                    denied,
                    Denied::Capability
                        | Denied::UnknownResource
                        | Denied::MethodNotPermitted
                        | Denied::Replayed
                ));
                Response::Error {
                    code: ErrorCode::Denied,
                    message: "denied".to_string(),
                }
            }
        }
    }
}

fn hex(bytes: &KeyBytes) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}
