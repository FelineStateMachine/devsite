//! Frames exchanged over an Iroh bidirectional stream, and their codec.
//!
//! One request frame and one response frame per stream. Frames are `postcard`-encoded and
//! prefixed with a u32 little-endian length.

use serde::{Deserialize, Serialize};

use crate::capability::SignedCapability;

/// Hard ceiling on any single frame. Bounds daemon memory against a hostile peer: the
/// length prefix is attacker-controlled, so it is checked *before* allocating.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Http(HttpRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// The grant authorizing this request. Required, not optional: a daemon must never
    /// have a code path where an absent capability means "allow".
    pub capability: SignedCapability,
    pub method: Method,
    /// Origin-relative path, e.g. `/` or `/chat`. Never an absolute URL — the daemon
    /// resolves the origin from its own configuration, never from the peer.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    Get,
    Head,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Http {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// Deliberately coarse. A peer that fails authorization learns only "denied" — never
/// whether the resource existed, whether the signature or the binding was the problem, or
/// anything else that would let it probe the daemon's configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Denied,
    BadRequest,
    UpstreamUnavailable,
    UpstreamTooLarge,
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("frame of {size} bytes exceeds the {MAX_FRAME_BYTES} byte limit")]
    TooLarge { size: usize },
    #[error("malformed frame: {0}")]
    Malformed(#[from] postcard::Error),
}

/// Encode a frame with its length prefix. Fails rather than emitting an oversized frame,
/// so a bug on our side can't produce something the peer will reject as hostile.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let payload = postcard::to_allocvec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge {
            size: payload.len(),
        });
    }
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Validate a length prefix before it is used to size an allocation.
pub fn frame_len(prefix: [u8; 4]) -> Result<usize, CodecError> {
    let size = u32::from_le_bytes(prefix) as usize;
    if size > MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge { size });
    }
    Ok(size)
}

pub fn decode<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, CodecError> {
    Ok(postcard::from_bytes(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_capability() -> SignedCapability {
        use crate::capability::{CapabilityClaims, Permission};
        use crate::{AccountId, ResourceId};

        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let claims = CapabilityClaims {
            issuer: "https://dev.site".to_string(),
            viewer: AccountId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            audience: [7; 32],
            browser_key: [8; 32],
            permission: Permission::HttpRead,
            issued_at: 0,
            expires_at: 300,
            nonce: [3; 16],
        };
        SignedCapability::sign(&claims, &key).unwrap()
    }

    #[test]
    fn frames_round_trip() {
        let request = Request::Http(HttpRequest {
            capability: sample_capability(),
            method: Method::Get,
            path: "/".to_string(),
        });
        let encoded = encode(&request).unwrap();
        let size = frame_len(encoded[..4].try_into().unwrap()).unwrap();
        assert_eq!(size, encoded.len() - 4);

        let decoded: Request = decode(&encoded[4..]).unwrap();
        let Request::Http(http) = decoded;
        assert_eq!(http.path, "/");
        assert_eq!(http.method, Method::Get);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocating() {
        let prefix = (MAX_FRAME_BYTES as u32 + 1).to_le_bytes();
        assert!(matches!(
            frame_len(prefix),
            Err(CodecError::TooLarge { .. })
        ));
        // The pathological case: a peer claiming ~4 GiB must not cause a 4 GiB allocation.
        assert!(matches!(
            frame_len(u32::MAX.to_le_bytes()),
            Err(CodecError::TooLarge { .. })
        ));
    }
}
