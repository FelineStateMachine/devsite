//! Types shared by every dev.site component: the CLI, the daemon, the control plane, and
//! native clients. No I/O lives here.

pub mod capability;
pub mod id;
pub mod wire;

pub use capability::{CapabilityClaims, CapabilityError, Permission, SignedCapability};
pub use id::{AccountId, IdParseError, ResourceId};
pub use wire::{ConnectRequest, ErrorCode, Request, Response};

/// Domain-separated statement signed by a daemon when enrolling or registering
/// its endpoint identity with the control plane.
pub fn machine_endpoint_proof_message(endpoint: &[u8; 32]) -> Vec<u8> {
    let mut message = b"dev.site machine endpoint proof v1\0".to_vec();
    message.extend_from_slice(endpoint);
    message
}

/// ALPN for the authorized bidirectional TCP stream protocol.
pub const ALPN: &[u8] = b"devsite/tcp/1";
