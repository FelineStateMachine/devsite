//! Short-lived, signed grants issued by the control plane and verified by a daemon.
//!
//! A capability is the only thing that persuades a daemon to talk to a local service. It
//! is deliberately narrow: one viewer, one resource, one daemon, one browser key, one
//! permission, a few minutes.
//!
//! Public keys are carried as raw bytes rather than iroh types so this crate stays free of
//! iroh (and therefore trivially portable). The daemon converts its `EndpointId` with
//! `as_bytes()` when comparing.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{AccountId, ResourceId};

/// Raw Ed25519/iroh public key bytes.
pub type KeyBytes = [u8; 32];

/// How long a freshly issued capability remains valid. Short enough that a leaked token is
/// of little use, long enough to survive a slow relay connection.
pub const DEFAULT_LIFETIME_SECS: u64 = 180;

/// Tolerance for clock skew between the control plane and a daemon.
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// GET/HEAD only. The daemon refuses anything that could mutate the local service.
    HttpRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    pub issuer: String,
    /// Who is being granted access, by immutable account id — never by handle.
    pub viewer: AccountId,
    pub resource: ResourceId,
    /// The daemon this grant is addressed to. A daemon rejects capabilities minted for a
    /// different audience, so one daemon cannot replay a grant against another.
    pub audience: KeyBytes,
    /// The browser endpoint key this grant is bound to. The daemon checks it against the
    /// authenticated peer of the connection, which is what makes a stolen capability
    /// useless without the matching private key.
    pub browser_key: KeyBytes,
    pub permission: Permission,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Unique per issuance, so a daemon can refuse to serve the same grant twice.
    pub nonce: [u8; 16],
}

/// A capability plus its signature.
///
/// `claims` holds the exact bytes that were signed. Verification checks the signature
/// against *these* bytes and only then deserializes them — re-encoding before verifying
/// would make the result depend on serializer stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCapability {
    claims: Vec<u8>,
    /// 64 raw signature bytes. Held as a `Vec` because serde has no impl for `[u8; 64]`;
    /// the length is checked during verification rather than trusted.
    signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("signature does not verify")]
    BadSignature,
    #[error("capability is malformed")]
    Malformed,
    #[error("capability has expired")]
    Expired,
    #[error("capability is not valid yet")]
    NotYetValid,
    #[error("capability was issued for a different daemon")]
    WrongAudience,
    #[error("capability is bound to a different browser key")]
    WrongBrowserKey,
}

impl SignedCapability {
    pub fn sign(claims: &CapabilityClaims, key: &SigningKey) -> Result<Self, CapabilityError> {
        let bytes = postcard::to_allocvec(claims).map_err(|_| CapabilityError::Malformed)?;
        let signature = key.sign(&bytes);
        Ok(Self {
            claims: bytes,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Verify the signature and return the claims.
    ///
    /// This checks only what the signature attests to. Context-dependent checks — audience,
    /// expiry, browser binding — live in [`Self::verify_for`], which callers should prefer.
    pub fn verify(&self, key: &VerifyingKey) -> Result<CapabilityClaims, CapabilityError> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CapabilityError::Malformed)?;
        key.verify(&self.claims, &Signature::from_bytes(&signature))
            .map_err(|_| CapabilityError::BadSignature)?;
        postcard::from_bytes(&self.claims).map_err(|_| CapabilityError::Malformed)
    }

    /// Full verification as a daemon must perform it.
    ///
    /// `peer` is the authenticated remote endpoint of the connection the capability
    /// arrived on — not anything the peer told us about itself.
    pub fn verify_for(
        &self,
        key: &VerifyingKey,
        audience: &KeyBytes,
        peer: &KeyBytes,
        now: u64,
    ) -> Result<CapabilityClaims, CapabilityError> {
        let claims = self.verify(key)?;

        if &claims.audience != audience {
            return Err(CapabilityError::WrongAudience);
        }
        // The check the whole design rests on: the capability names a browser key, and the
        // connection proves possession of one. They must be the same key.
        if &claims.browser_key != peer {
            return Err(CapabilityError::WrongBrowserKey);
        }
        if now > claims.expires_at {
            return Err(CapabilityError::Expired);
        }
        if claims.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(CapabilityError::NotYetValid);
        }
        Ok(claims)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("a signed capability always serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CapabilityError> {
        postcard::from_bytes(bytes).map_err(|_| CapabilityError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn claims(audience: KeyBytes, browser_key: KeyBytes) -> CapabilityClaims {
        CapabilityClaims {
            issuer: "https://dev.site".to_string(),
            viewer: AccountId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            audience,
            browser_key,
            permission: Permission::HttpRead,
            issued_at: NOW,
            expires_at: NOW + DEFAULT_LIFETIME_SECS,
            nonce: [3; 16],
        }
    }

    #[test]
    fn a_well_formed_capability_verifies() {
        let key = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        let verified = cap
            .verify_for(&key.verifying_key(), &[7; 32], &[8; 32], NOW + 1)
            .unwrap();
        assert_eq!(verified.permission, Permission::HttpRead);
    }

    #[test]
    fn survives_a_round_trip_through_bytes() {
        let key = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        let restored = SignedCapability::from_bytes(&cap.to_bytes()).unwrap();
        assert!(restored
            .verify_for(&key.verifying_key(), &[7; 32], &[8; 32], NOW)
            .is_ok());
    }

    #[test]
    fn rejects_a_capability_signed_by_someone_else() {
        let attacker = signing_key(1);
        let real = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &attacker).unwrap();
        assert_eq!(
            cap.verify_for(&real.verifying_key(), &[7; 32], &[8; 32], NOW),
            Err(CapabilityError::BadSignature)
        );
    }

    #[test]
    fn rejects_use_from_a_different_browser_key() {
        // Bob hands his capability to someone else, or it leaks from the network. The
        // thief connects with their own endpoint key, and the binding fails.
        let key = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        assert_eq!(
            cap.verify_for(&key.verifying_key(), &[7; 32], &[99; 32], NOW),
            Err(CapabilityError::WrongBrowserKey)
        );
    }

    #[test]
    fn rejects_replay_against_a_different_daemon() {
        let key = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        assert_eq!(
            cap.verify_for(&key.verifying_key(), &[123; 32], &[8; 32], NOW),
            Err(CapabilityError::WrongAudience)
        );
    }

    #[test]
    fn rejects_expired_capabilities() {
        let key = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        assert_eq!(
            cap.verify_for(
                &key.verifying_key(),
                &[7; 32],
                &[8; 32],
                NOW + DEFAULT_LIFETIME_SECS + 1
            ),
            Err(CapabilityError::Expired)
        );
    }

    #[test]
    fn rejects_capabilities_from_the_future_beyond_skew() {
        let key = signing_key(9);
        let cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        // Within tolerance: fine.
        assert!(cap
            .verify_for(&key.verifying_key(), &[7; 32], &[8; 32], NOW - 10)
            .is_ok());
        // Well beyond it: refuse.
        assert_eq!(
            cap.verify_for(&key.verifying_key(), &[7; 32], &[8; 32], NOW - 600),
            Err(CapabilityError::NotYetValid)
        );
    }

    #[test]
    fn rejects_tampered_claims() {
        let key = signing_key(9);
        let mut cap = SignedCapability::sign(&claims([7; 32], [8; 32]), &key).unwrap();
        // Flip a byte in the signed payload; the signature must no longer match.
        cap.claims[4] ^= 0xff;
        assert_eq!(
            cap.verify_for(&key.verifying_key(), &[7; 32], &[8; 32], NOW),
            Err(CapabilityError::BadSignature)
        );
    }
}
