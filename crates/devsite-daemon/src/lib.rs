//! The daemon: an Iroh endpoint that proxies *authorized* requests to local services.
//!
//! It has no inbound port. It reaches the world through a relay, and it decides for itself
//! whether to honour a request by verifying a capability signed by the control plane —
//! the control plane never touches this traffic.

pub mod config;
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
use tokio::io::{copy, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};

use crate::config::{DaemonConfig, HostedService};
use crate::verify::{Denied, ReplayGuard};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Daemon {
    endpoint: Endpoint,
    config: RwLock<DaemonConfig>,
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

        Ok(Self {
            endpoint,
            config: RwLock::new(config),
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

    /// Stop accepting new peers and close the Iroh endpoint cleanly. Service
    /// managers do not need a platform-specific integration; terminating the
    /// foreground command is still the whole lifecycle contract.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    /// Replace only the resource map while the endpoint keeps its identity and
    /// open connections. This is intentionally platform-neutral: service
    /// managers only need to keep `devsite daemon run` alive.
    pub async fn replace_resources(&self, resources: Vec<HostedService>) -> bool {
        let mut config = self.config.write().await;
        if config.resources == resources {
            return false;
        }
        config.resources = resources;
        true
    }

    /// Accept connections until the endpoint closes.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let resources = self.config.read().await.resources.len();
        tracing::info!(
            resources,
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
        // and the capability's client binding is checked against it.
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

        let request = match wire::decode::<Request>(&payload) {
            Ok(request) => request,
            Err(err) => {
                tracing::debug!("malformed frame from {}: {err:#}", hex(peer));
                return send_response(
                    &mut send,
                    Response::Error {
                        code: ErrorCode::BadRequest,
                        message: "malformed request".to_string(),
                    },
                )
                .await;
            }
        };
        let Request::Connect(request) = request;
        let targets = self.config.read().await.targets();
        let my_endpoint = self.endpoint_key();
        let now = now_secs();

        let authorized = {
            let mut replay = self.replay.lock().await;
            verify::authorize(
                &request.capability,
                &self.control_plane_key,
                &my_endpoint,
                peer,
                &targets,
                &mut replay,
                now,
            )
        };

        let authorized = match authorized {
            Ok(authorized) => authorized,
            Err(denied) => {
                // Logged with detail locally, reported to the peer as a bare "denied".
                tracing::warn!(peer = %hex(peer), reason = ?denied, "denied request");
                debug_assert!(matches!(
                    denied,
                    Denied::Capability | Denied::UnknownResource | Denied::Replayed
                ));
                return send_response(
                    &mut send,
                    Response::Error {
                        code: ErrorCode::Denied,
                        message: "denied".to_string(),
                    },
                )
                .await;
            }
        };

        let upstream = match TcpStream::connect(authorized.target).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!(target = %authorized.target, "local service did not accept TCP: {err}");
                return send_response(
                    &mut send,
                    Response::Error {
                        code: ErrorCode::UpstreamUnavailable,
                        message: "local service did not accept a connection".to_string(),
                    },
                )
                .await;
            }
        };

        tracing::info!(
            viewer = %authorized.claims.viewer,
            resource = %authorized.claims.resource,
            target = %authorized.target,
            "opened service stream"
        );
        send.write_all(&wire::encode(&Response::Connected)?)
            .await
            .context("writing connect response")?;

        let (mut upstream_read, mut upstream_write) = upstream.into_split();
        let client_to_service = async {
            copy(&mut recv, &mut upstream_write)
                .await
                .context("forwarding client bytes")?;
            upstream_write.shutdown().await.ok();
            Ok::<_, anyhow::Error>(())
        };
        let service_to_client = async {
            copy(&mut upstream_read, &mut send)
                .await
                .context("forwarding service bytes")?;
            send.finish().context("finishing service stream")?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(client_to_service, service_to_client)?;
        Ok(())
    }
}

async fn send_response(send: &mut iroh::endpoint::SendStream, response: Response) -> Result<()> {
    send.write_all(&wire::encode(&response)?)
        .await
        .context("writing response frame")?;
    send.finish().context("finishing response stream")?;
    send.stopped().await.ok();
    Ok(())
}

fn hex(bytes: &KeyBytes) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}
