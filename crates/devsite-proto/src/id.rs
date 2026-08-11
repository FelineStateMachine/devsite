//! Immutable, opaque identifiers.
//!
//! Handles such as `@alice` are presentation names only. Every authorization decision in
//! the system is made against these IDs, which never change and are never reassigned.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ENCODING: data_encoding::Encoding = data_encoding::BASE32_NOPAD;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Mint a fresh, unguessable id.
            pub fn generate() -> Self {
                let mut bytes = [0u8; 16];
                getrandom::fill(&mut bytes).expect("system randomness is available");
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, ENCODING.encode(&self.0).to_lowercase())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let body = s
                    .strip_prefix(concat!($prefix, "_"))
                    .ok_or(IdParseError::BadPrefix { expected: $prefix })?;
                let raw = ENCODING
                    .decode(body.to_uppercase().as_bytes())
                    .map_err(|_| IdParseError::BadEncoding)?;
                let bytes: [u8; 16] = raw.try_into().map_err(|_| IdParseError::BadLength)?;
                Ok(Self(bytes))
            }
        }

        // Strings in JSON (readable API payloads), raw bytes in postcard (compact wire
        // frames and stable signing input).
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.serialize_str(&self.to_string())
                } else {
                    self.0.serialize(s)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                if d.is_human_readable() {
                    let text = String::deserialize(d)?;
                    text.parse().map_err(serde::de::Error::custom)
                } else {
                    <[u8; 16]>::deserialize(d).map(Self)
                }
            }
        }
    };
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdParseError {
    #[error("expected an id beginning with `{expected}_`")]
    BadPrefix { expected: &'static str },
    #[error("id body is not valid base32")]
    BadEncoding,
    #[error("id body is not 16 bytes")]
    BadLength,
}

opaque_id!(AccountId, "acct");
opaque_id!(ResourceId, "res");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_string() {
        let id = ResourceId::from_bytes([7u8; 16]);
        let text = id.to_string();
        assert!(text.starts_with("res_"));
        assert_eq!(ResourceId::from_str(&text).unwrap(), id);
    }

    #[test]
    fn rejects_the_wrong_prefix() {
        let account = AccountId::from_bytes([3u8; 16]).to_string();
        // An AccountId must never parse as a ResourceId, or a confused-deputy bug becomes
        // possible where one namespace's id authorizes access in the other.
        assert_eq!(
            ResourceId::from_str(&account),
            Err(IdParseError::BadPrefix { expected: "res" })
        );
    }

    #[test]
    fn rejects_truncated_ids() {
        assert_eq!(
            ResourceId::from_str("res_aaaa"),
            Err(IdParseError::BadLength)
        );
    }

    #[test]
    fn postcard_round_trip_is_compact() {
        let id = ResourceId::from_bytes([9u8; 16]);
        let bytes = postcard::to_allocvec(&id).unwrap();
        assert_eq!(bytes.len(), 16, "ids must not be length-prefixed on the wire");
        assert_eq!(postcard::from_bytes::<ResourceId>(&bytes).unwrap(), id);
    }
}
