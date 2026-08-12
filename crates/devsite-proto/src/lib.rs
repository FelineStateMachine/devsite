//! Types shared by every dev.site component: the CLI, the daemon, the control plane, and
//! native clients. No I/O lives here.

pub mod access_plan;
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

/// Canonical statement signed by a short-lived client endpoint when asking a
/// trusted machine to broker service access on its behalf.
pub fn service_grant_request_message(
    request_id: &str,
    service: &str,
    requester_endpoint: &[u8; 32],
    expires_at: u64,
) -> Vec<u8> {
    let mut message = b"dev.site service grant request v1\0".to_vec();
    push_field(&mut message, request_id.as_bytes());
    push_field(&mut message, service.as_bytes());
    push_field(&mut message, requester_endpoint);
    message.extend_from_slice(&expires_at.to_be_bytes());
    message
}

/// Canonical statement signed by the enrolled broker endpoint when issuing an
/// endpoint-bound session for one resolved resource.
pub fn service_grant_issue_message(
    request_id: &str,
    resource_id: &str,
    requester_endpoint: &[u8; 32],
    expires_at: u64,
) -> Vec<u8> {
    let mut message = b"dev.site service grant issue v1\0".to_vec();
    push_field(&mut message, request_id.as_bytes());
    push_field(&mut message, resource_id.as_bytes());
    push_field(&mut message, requester_endpoint);
    message.extend_from_slice(&expires_at.to_be_bytes());
    message
}

fn push_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u64).to_be_bytes());
    message.extend_from_slice(field);
}

/// ALPN for the authorized bidirectional TCP stream protocol.
pub const ALPN: &[u8] = b"devsite/tcp/1";
