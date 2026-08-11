//! Deciding whether to honour a request.
//!
//! Everything here is deliberately paranoid and deliberately quiet: the caller learns only
//! that it was denied, never *why*. A peer that could distinguish "no such resource" from
//! "not shared with you" could enumerate a profile's private services.

use std::collections::HashMap;

use devsite_proto::capability::{CapabilityClaims, KeyBytes, Permission, SignedCapability};
use devsite_proto::wire::Method;
use devsite_proto::ResourceId;
use ed25519_dalek::VerifyingKey;
use url::Url;

/// A request that passed every check, carrying the origin it resolved to.
#[derive(Debug)]
pub struct Authorized {
    pub claims: CapabilityClaims,
    pub origin: Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// Signature, audience, binding, or expiry failed.
    Capability,
    /// Well-formed and correctly signed, but names a resource this daemon does not serve.
    UnknownResource,
    /// The grant does not cover this method.
    MethodNotPermitted,
    /// This exact capability has already been used.
    Replayed,
}

/// Remembers recently used capability nonces so a grant cannot be redeemed twice.
///
/// Bounded by expiry rather than by count: entries are pruned once the capability they
/// describe could no longer be valid anyway, so memory tracks issuance rate, not uptime.
#[derive(Default)]
pub struct ReplayGuard {
    seen: HashMap<[u8; 16], u64>,
}

impl ReplayGuard {
    /// Record a nonce. Returns false if it had already been used.
    pub fn admit(&mut self, nonce: [u8; 16], expires_at: u64, now: u64) -> bool {
        self.seen.retain(|_, expiry| *expiry > now);
        if self.seen.contains_key(&nonce) {
            return false;
        }
        self.seen.insert(nonce, expires_at);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// The full check, in the order that leaks the least.
///
/// `peer` must come from the connection's authenticated identity — iroh's
/// `Connection::remote_id()` — and never from anything inside the request frame.
pub fn authorize(
    capability: &SignedCapability,
    method: Method,
    control_plane_key: &VerifyingKey,
    my_endpoint: &KeyBytes,
    peer: &KeyBytes,
    origins: &HashMap<ResourceId, Url>,
    replay: &mut ReplayGuard,
    now: u64,
) -> Result<Authorized, Denied> {
    // Cryptography first: signature, audience, browser binding, expiry. Until this passes
    // the claims are just bytes a stranger sent us.
    let claims = capability
        .verify_for(control_plane_key, my_endpoint, peer, now)
        .map_err(|_| Denied::Capability)?;

    match claims.permission {
        Permission::HttpRead => {
            if !matches!(method, Method::Get | Method::Head) {
                return Err(Denied::MethodNotPermitted);
            }
        }
    }

    let origin = origins
        .get(&claims.resource)
        .ok_or(Denied::UnknownResource)?
        .clone();

    // Last, because consuming the nonce has a side effect: a request that would have been
    // refused anyway must not burn a legitimate capability.
    if !replay.admit(claims.nonce, claims.expires_at, now) {
        return Err(Denied::Replayed);
    }

    Ok(Authorized { claims, origin })
}

#[cfg(test)]
mod tests {
    use devsite_proto::capability::DEFAULT_LIFETIME_SECS;
    use devsite_proto::{AccountId, ResourceId};
    use ed25519_dalek::SigningKey;

    use super::*;

    const NOW: u64 = 1_760_000_000;
    const DAEMON: KeyBytes = [7; 32];
    const BROWSER: KeyBytes = [8; 32];

    fn resource() -> ResourceId {
        ResourceId::from_bytes([2; 16])
    }

    fn origins() -> HashMap<ResourceId, Url> {
        HashMap::from([(resource(), Url::parse("http://127.0.0.1:4101").unwrap())])
    }

    fn claims_with(nonce: [u8; 16], res: ResourceId) -> CapabilityClaims {
        CapabilityClaims {
            issuer: "https://dev.site".to_string(),
            viewer: AccountId::from_bytes([1; 16]),
            resource: res,
            audience: DAEMON,
            browser_key: BROWSER,
            permission: Permission::HttpRead,
            issued_at: NOW,
            expires_at: NOW + DEFAULT_LIFETIME_SECS,
            nonce,
        }
    }

    fn run(
        key: &SigningKey,
        claims: &CapabilityClaims,
        peer: &KeyBytes,
        replay: &mut ReplayGuard,
    ) -> Result<Authorized, Denied> {
        let cap = SignedCapability::sign(claims, key).unwrap();
        authorize(
            &cap,
            Method::Get,
            &key.verifying_key(),
            &DAEMON,
            peer,
            &origins(),
            replay,
            NOW,
        )
    }

    #[test]
    fn allows_a_valid_request() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut replay = ReplayGuard::default();
        let ok = run(&key, &claims_with([1; 16], resource()), &BROWSER, &mut replay).unwrap();
        assert_eq!(ok.origin.as_str(), "http://127.0.0.1:4101/");
    }

    #[test]
    fn denies_a_capability_bound_to_another_browser() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut replay = ReplayGuard::default();
        let denied = run(&key, &claims_with([1; 16], resource()), &[99; 32], &mut replay)
            .unwrap_err();
        assert_eq!(denied, Denied::Capability);
    }

    #[test]
    fn denies_a_resource_this_daemon_does_not_serve() {
        // Correctly signed and correctly bound, but for a resource id that is not in the
        // local map — e.g. a capability meant for a service the owner has since removed.
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut replay = ReplayGuard::default();
        let stranger = ResourceId::from_bytes([44; 16]);
        let denied =
            run(&key, &claims_with([1; 16], stranger), &BROWSER, &mut replay).unwrap_err();
        assert_eq!(denied, Denied::UnknownResource);
    }

    #[test]
    fn denies_a_second_use_of_the_same_capability() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut replay = ReplayGuard::default();
        let claims = claims_with([1; 16], resource());
        assert!(run(&key, &claims, &BROWSER, &mut replay).is_ok());
        assert_eq!(
            run(&key, &claims, &BROWSER, &mut replay).unwrap_err(),
            Denied::Replayed
        );
    }

    #[test]
    fn a_denied_request_does_not_consume_the_nonce() {
        // If a wrong-peer attempt burned the nonce, an attacker who merely observed a
        // capability could deny the legitimate viewer their one use of it.
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut replay = ReplayGuard::default();
        let claims = claims_with([1; 16], resource());

        assert!(run(&key, &claims, &[99; 32], &mut replay).is_err());
        assert!(replay.is_empty(), "a failed attempt must not record a nonce");
        assert!(run(&key, &claims, &BROWSER, &mut replay).is_ok());
    }

    #[test]
    fn replay_guard_forgets_expired_nonces() {
        let mut replay = ReplayGuard::default();
        assert!(replay.admit([1; 16], NOW + 60, NOW));
        assert!(!replay.admit([1; 16], NOW + 60, NOW));
        // Once every recorded nonce has expired the table drains rather than growing
        // without bound.
        assert!(replay.admit([2; 16], NOW + 3600, NOW + 61));
        assert_eq!(replay.len(), 1);
    }
}
