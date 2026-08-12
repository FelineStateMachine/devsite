//! Types shared by every dev.site component: the CLI, the daemon, the control plane, and
//! native clients. No I/O lives here.

pub mod capability;
pub mod id;
pub mod wire;

pub use capability::{CapabilityClaims, CapabilityError, Permission, SignedCapability};
pub use id::{AccountId, IdParseError, ResourceId};
pub use wire::{ConnectRequest, ErrorCode, Request, Response};

/// ALPN for the authorized bidirectional TCP stream protocol.
pub const ALPN: &[u8] = b"devsite/tcp/1";
