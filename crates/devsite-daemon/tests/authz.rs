//! The authorization matrix, exercised over real Iroh against real local TCP services.
//!
//! These run the same `devsite-client` code the CLI runs. Capabilities are minted directly
//! by a test issuer rather than by the
//! control plane, which keeps the tests focused on what the *daemon* enforces — the
//! control plane's own "may this account have a capability at all" rules are covered by the
//! policy tests in devsite-server.
//!
//! Negative cases assert `ConnectError::Denied` specifically, never merely "an error". A
//! relay timeout is also an error, and a test that accepted one would report a working
//! authorization check on a daemon that was simply unreachable.
//!
//! Endpoints are shared across cases: reaching a relay is slow, and the public relays
//! rate-limit, so binding one endpoint per assertion makes the suite flaky rather than
//! thorough.

use std::sync::Arc;

use devsite_client::{ClientEndpoint, ConnectError, ServiceStream};
use devsite_daemon::config::{DaemonConfig, HostedService, Visibility};
use devsite_daemon::Daemon;
use devsite_proto::capability::{
    CapabilityClaims, KeyBytes, Permission, SignedCapability, DEFAULT_LIFETIME_SECS,
};
use devsite_proto::{AccountId, ResourceId};
use ed25519_dalek::SigningKey;
use iroh::{EndpointAddr, RelayUrl, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const HERMES: &str = "hermes";
const AGENT: &str = "agent";

async fn spawn_service(name: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                let response = format!("{name}:{}", String::from_utf8_lossy(&buf));
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    target
}

struct Harness {
    daemon: Arc<Daemon>,
    daemon_key: KeyBytes,
    relay: RelayUrl,
    signing_key: SigningKey,
    hermes: ResourceId,
    agent: ResourceId,
    unknown: ResourceId,
    /// The legitimate client.
    client: ClientEndpoint,
    /// A second client, for anything about one client using another's grant.
    mallory: ClientEndpoint,
}

impl Harness {
    async fn start() -> Self {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let hermes = ResourceId::generate();
        let agent = ResourceId::generate();

        let config = DaemonConfig {
            server_url: Some("https://dev.site".into()),
            machine_credential: Some("test".into()),
            control_plane_key: Some(
                data_encoding::HEXLOWER.encode(signing_key.verifying_key().as_bytes()),
            ),
            resources: vec![
                HostedService {
                    resource_id: hermes,
                    name: "Hermes".into(),
                    target: spawn_service(HERMES).await,
                    visibility: Visibility::Private,
                },
                HostedService {
                    resource_id: agent,
                    name: "Agent".into(),
                    target: spawn_service(AGENT).await,
                    visibility: Visibility::Shared,
                },
            ],
        };

        let daemon = Arc::new(Daemon::bind(SecretKey::generate(), config).await.unwrap());
        let daemon_key = daemon.endpoint_key();
        let relay = daemon
            .endpoint()
            .addr()
            .relay_urls()
            .next()
            .expect("daemon should have a relay")
            .clone();

        tokio::spawn(Arc::clone(&daemon).serve());

        let (client, mallory) = tokio::join!(ClientEndpoint::create(), ClientEndpoint::create());

        Self {
            daemon,
            daemon_key,
            relay,
            signing_key,
            hermes,
            agent,
            unknown: ResourceId::generate(),
            client: client.unwrap(),
            mallory: mallory.unwrap(),
        }
    }

    fn now(&self) -> u64 {
        devsite_daemon::now_secs()
    }

    /// Mint a capability with every field under the test's control.
    fn mint(
        &self,
        key: &SigningKey,
        resource: ResourceId,
        audience: KeyBytes,
        client_key: KeyBytes,
        issued_at: u64,
        expires_at: u64,
    ) -> SignedCapability {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        SignedCapability::sign(
            &CapabilityClaims {
                issuer: "https://dev.site".into(),
                viewer: AccountId::generate(),
                resource,
                audience,
                client_key,
                permission: Permission::TcpConnect,
                issued_at,
                expires_at,
                nonce,
            },
            key,
        )
        .unwrap()
    }

    /// An ordinary, valid capability for `resource`, bound to the legitimate client.
    fn valid(&self, resource: ResourceId) -> SignedCapability {
        let now = self.now();
        self.mint(
            &self.signing_key,
            resource,
            self.daemon_key,
            *self.client.endpoint_id().as_bytes(),
            now,
            now + DEFAULT_LIFETIME_SECS,
        )
    }

    async fn connect_as(
        &self,
        who: &ClientEndpoint,
        capability: SignedCapability,
        input: &str,
    ) -> Result<String, ConnectError> {
        // The relay is pinned rather than looked up. In the browser a bare
        // endpoint id is enough — the daemon publishes its address and the client
        // resolves it — but that path depends on a third-party lookup service,
        // and these tests are about what the daemon enforces, not about how it
        // was found. Handing the address over directly keeps a denial a denial
        // and never a lookup that was slow.
        let addr =
            EndpointAddr::from(self.daemon.endpoint().id()).with_relay_url(self.relay.clone());
        let ServiceStream { mut send, mut recv } = who.connect(addr, capability).await?;
        send.write_all(input.as_bytes())
            .await
            .map_err(|err| ConnectError::Transport(err.into()))?;
        send.finish()
            .map_err(|err| ConnectError::Transport(err.into()))?;
        let output = recv
            .read_to_end(1024 * 1024)
            .await
            .map_err(|err| ConnectError::Transport(err.into()))?;
        Ok(String::from_utf8_lossy(&output).into_owned())
    }

    async fn connect(&self, capability: SignedCapability) -> Result<String, ConnectError> {
        self.connect_as(&self.client, capability, "hello").await
    }

    /// Assert the daemon reached a verdict and refused, rather than being unreachable.
    async fn assert_denied(&self, capability: SignedCapability, case: &str) {
        match self.connect(capability).await {
            Err(ConnectError::Denied) => {}
            Err(ConnectError::Transport(err)) => {
                panic!("{case}: never reached a verdict — {err:#}")
            }
            Err(other) => panic!("{case}: expected a denial, got {other}"),
            Ok(body) => panic!("{case}: expected a denial, but the service answered: {body}"),
        }
    }
}

/// The whole matrix runs in one test, on one runtime.
///
/// Separate `#[tokio::test]` functions each get their own runtime, and the daemon's accept
/// loop lives on whichever one built the shared harness first. Once that runtime shuts
/// down the daemon stops answering and every later case hangs — so the cases are sequenced
/// here instead, which is also faster and easier on the public relays.
#[tokio::test]
async fn authorization_matrix() {
    let h = Harness::start().await;

    valid_capability_opens_a_stream(&h).await;
    each_resource_maps_to_its_own_service(&h).await;
    capability_bound_to_another_client_is_refused(&h).await;
    capabilities_that_fail_verification_are_refused(&h).await;
    a_capability_cannot_be_redeemed_twice(&h).await;
    denials_reveal_nothing_about_why(&h).await;
}

async fn valid_capability_opens_a_stream(h: &Harness) {
    let response = h
        .connect(h.valid(h.hermes))
        .await
        .expect("a valid capability should be honoured");
    assert_eq!(response, "hermes:hello");
}

async fn each_resource_maps_to_its_own_service(h: &Harness) {
    // Proves the daemon routes by resource id rather than serving one default target —
    // otherwise "Bob can reach Agent" would quietly also mean "Bob can reach Hermes".
    let response = h.connect(h.valid(h.agent)).await.unwrap();
    assert_eq!(response, "agent:hello");
}

async fn capability_bound_to_another_client_is_refused(h: &Harness) {
    // The core claim: a leaked or forwarded capability is useless without the private key
    // it was bound to. Mallory presents the client's capability from her own endpoint.
    let stolen = h.valid(h.agent);
    match h.connect_as(&h.mallory, stolen, "stolen").await {
        Err(ConnectError::Denied) => {}
        Err(ConnectError::Transport(err)) => panic!("never reached a verdict — {err:#}"),
        Err(other) => panic!("expected a denial, got {other}"),
        Ok(body) => panic!("a rebound capability was honoured: {body}"),
    }
}

async fn capabilities_that_fail_verification_are_refused(h: &Harness) {
    let now = h.now();
    let mine = *h.client.endpoint_id().as_bytes();

    // Signed by someone who is not the control plane.
    h.assert_denied(
        h.mint(
            &SigningKey::from_bytes(&[7; 32]),
            h.hermes,
            h.daemon_key,
            mine,
            now,
            now + DEFAULT_LIFETIME_SECS,
        ),
        "forged signature",
    )
    .await;

    // Expired.
    h.assert_denied(
        h.mint(
            &h.signing_key,
            h.hermes,
            h.daemon_key,
            mine,
            now - 600,
            now - 300,
        ),
        "expired",
    )
    .await;

    // Addressed to a different daemon.
    h.assert_denied(
        h.mint(
            &h.signing_key,
            h.hermes,
            [99; 32],
            mine,
            now,
            now + DEFAULT_LIFETIME_SECS,
        ),
        "wrong audience",
    )
    .await;

    // Correctly signed and bound, but names a resource this daemon does not serve.
    h.assert_denied(h.valid(h.unknown), "unknown resource")
        .await;
}

async fn a_capability_cannot_be_redeemed_twice(h: &Harness) {
    let capability = h.valid(h.hermes);
    assert!(h.connect(capability.clone()).await.is_ok());
    h.assert_denied(capability, "replayed capability").await;
}

async fn denials_reveal_nothing_about_why(h: &Harness) {
    // A peer must not be able to tell "no such resource" from "not signed correctly" —
    // that difference is enough to enumerate a profile's private services.
    let now = h.now();
    let mine = *h.client.endpoint_id().as_bytes();

    let unknown = h.connect(h.valid(h.unknown)).await.unwrap_err();
    let forged = h
        .connect(h.mint(
            &SigningKey::from_bytes(&[7; 32]),
            h.hermes,
            h.daemon_key,
            mine,
            now,
            now + DEFAULT_LIFETIME_SECS,
        ))
        .await
        .unwrap_err();

    assert!(matches!(unknown, ConnectError::Denied));
    assert!(matches!(forged, ConnectError::Denied));
    assert_eq!(
        unknown.to_string(),
        forged.to_string(),
        "denial messages must be indistinguishable"
    );
}

#[test]
fn resource_ids_do_not_collide() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        assert!(
            seen.insert(ResourceId::generate()),
            "generated a duplicate id"
        );
    }
}
