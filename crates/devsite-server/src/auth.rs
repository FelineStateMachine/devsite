//! Provider-neutral identities and the sessions that follow.
//!
//! Login adapters end at `ExternalIdentity`. Nothing downstream knows which provider
//! authenticated it; it only trusts the opaque dev.site session minted for that identity.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// How long a dev.site session lasts.
pub const SESSION_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;

/// The only value a login adapter is allowed to hand to the application.
///
/// For OIDC, the namespace is the exact `iss` claim and the subject is `sub`; that pair,
/// rather than either value alone, is the stable external identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub namespace: String,
    pub subject: String,
}

/// Mint an opaque session token. Only its hash is stored.
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom_fill(&mut bytes);
    data_encoding::BASE64URL_NOPAD.encode(&bytes)
}

/// Long-lived bearer credential for one named machine. The prefix keeps it
/// recognizable in password managers and logs without weakening its entropy.
pub fn generate_machine_token() -> String {
    format!("dsm_{}", generate_session_token())
}

/// One-use plaintext bootstrap material. Enrollment consumes it and returns
/// the endpoint-bound machine credential.
pub fn generate_machine_ticket() -> String {
    format!("dmt_{}", generate_session_token())
}

pub fn generate_machine_credential_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom_fill(&mut bytes);
    format!(
        "machine_{}",
        data_encoding::BASE32_NOPAD
            .encode(&bytes)
            .to_ascii_lowercase()
    )
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    data_encoding::HEXLOWER.encode(&digest)
}

fn getrandom_fill(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

/// Handles are the presentation layer only, but they still end up in URLs and in shell
/// commands, so keep them boring.
pub fn validate_handle(handle: &str) -> Result<String> {
    let handle = handle.trim().trim_start_matches('@');
    if handle.len() < 2 || handle.len() > 32 {
        bail!("handles must be between 2 and 32 characters");
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("handles may contain only letters, digits, hyphens and underscores");
    }
    if handle.starts_with('-') || handle.starts_with('_') {
        bail!("handles must start with a letter or digit");
    }
    let handle = handle.to_ascii_lowercase();
    // This is deliberately not a profanity filter. These names imply an
    // official dev.site identity and are the small set worth reserving.
    const RESERVED: &[&str] = &["admin", "devsite", "security", "support"];
    if RESERVED.contains(&handle.as_str()) {
        bail!("that handle is reserved");
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_tokens_are_unpredictable_and_stored_hashed() {
        let a = generate_session_token();
        let b = generate_session_token();
        assert_ne!(a, b);
        assert!(a.len() >= 43);
        assert_ne!(
            hash_token(&a),
            a,
            "the raw token must never be the stored value"
        );
        assert_eq!(hash_token(&a), hash_token(&a));
        assert!(generate_machine_token().starts_with("dsm_"));
        assert!(generate_machine_ticket().starts_with("dmt_"));
    }

    #[test]
    fn accepts_reasonable_handles() {
        assert_eq!(validate_handle("@Alice").unwrap(), "alice");
        assert_eq!(validate_handle("bob_2").unwrap(), "bob_2");
    }

    #[test]
    fn rejects_handles_that_would_be_trouble_in_a_url_or_shell() {
        for bad in [
            "a",
            "",
            "has space",
            "semi;colon",
            "../etc",
            "-leading",
            "slash/es",
        ] {
            assert!(validate_handle(bad).is_err(), "{bad:?} should be rejected");
        }
        for reserved in ["admin", "DevSite", "security", "support"] {
            assert!(
                validate_handle(reserved).is_err(),
                "{reserved:?} should be reserved"
            );
        }
    }
}
