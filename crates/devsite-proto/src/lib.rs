//! Types shared by every dev.site component: the CLI, the daemon, the control plane, and
//! the browser WASM endpoint. No I/O lives here, so it compiles unchanged for wasm32.

pub mod capability;
pub mod id;
pub mod wire;

pub use capability::{CapabilityClaims, CapabilityError, Permission, SignedCapability};
pub use id::{AccountId, IdParseError, ResourceId};
pub use wire::{ErrorCode, HttpRequest, Method, Request, Response};

/// ALPN for the dev.site proxy protocol. Bumping the trailing version retires every
/// previously issued capability shape, since peers negotiate on this string.
pub const ALPN: &[u8] = b"devsite/http/0";
