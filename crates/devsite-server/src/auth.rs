//! Sign-in via Shoo, and the sessions that follow.
//!
//! Shoo is an OIDC broker for Google sign-in. The browser performs the authorize + PKCE
//! token exchange itself and hands us the resulting `id_token`; we verify it independently
//! against Shoo's JWKS and then mint our own session. Nothing downstream trusts the
//! `id_token` again — only our session cookie.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const ISSUER: &str = "https://shoo.dev";
pub const JWKS_URL: &str = "https://shoo.dev/.well-known/jwks.json";

/// How long a dev.site session lasts.
pub const SESSION_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;

/// Refetch JWKS at most this often, so key rotation is picked up without hammering Shoo.
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);

/// The claims we care about. `sub` is Shoo's pairwise subject: stable for our origin,
/// and uncorrelatable with the same person on any other site.
///
/// `exp` must stay declared even though nothing reads it directly — `jsonwebtoken`
/// enforces it during deserialization, and dropping the field would silently disable that.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Jwk {
    kid: String,
    x: String,
    y: String,
    #[serde(default)]
    alg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

pub struct ShooVerifier {
    /// `origin:<our origin>` — the audience Shoo stamps into tokens issued for us.
    ///
    /// Checking this exactly is what stops a token minted for some other site from being
    /// replayed at dev.site to impersonate its bearer.
    audience: String,
    http: reqwest::Client,
    cache: RwLock<Option<(Vec<Jwk>, Instant)>>,
}

impl ShooVerifier {
    /// `public_origin` is the exact origin the browser loads, e.g. `https://dev.site`.
    pub fn new(public_origin: &str) -> Self {
        Self {
            audience: format!("origin:{}", public_origin.trim_end_matches('/')),
            http: reqwest::Client::new(),
            cache: RwLock::new(None),
        }
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    async fn keys(&self) -> Result<Vec<Jwk>> {
        if let Some((keys, fetched)) = self.cache.read().unwrap().as_ref() {
            if fetched.elapsed() < JWKS_TTL {
                return Ok(keys.clone());
            }
        }

        let jwks: Jwks = self
            .http
            .get(JWKS_URL)
            .send()
            .await
            .context("fetching Shoo JWKS")?
            .error_for_status()
            .context("Shoo JWKS returned an error status")?
            .json()
            .await
            .context("parsing Shoo JWKS")?;

        *self.cache.write().unwrap() = Some((jwks.keys.clone(), Instant::now()));
        Ok(jwks.keys)
    }

    /// Verify an `id_token` and return its claims.
    ///
    /// The algorithm is pinned to ES256 rather than read from the token header: accepting
    /// whatever a token asks for is how `alg: none` and HMAC-confusion attacks work.
    pub async fn verify(&self, id_token: &str) -> Result<IdTokenClaims> {
        let header = jsonwebtoken::decode_header(id_token).context("unreadable token header")?;
        if header.alg != Algorithm::ES256 {
            bail!("unexpected token algorithm {:?}", header.alg);
        }
        let kid = header.kid.context("token has no key id")?;

        let keys = self.keys().await?;
        let jwk = keys
            .iter()
            .find(|k| k.kid == kid)
            .with_context(|| format!("no Shoo key matches kid {kid}"))?;
        if jwk.alg.as_deref().is_some_and(|alg| alg != "ES256") {
            bail!("Shoo key {kid} is not an ES256 key");
        }

        let key = DecodingKey::from_ec_components(&jwk.x, &jwk.y)
            .context("Shoo key is not a usable EC public key")?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .context("id_token failed verification")?;

        // jsonwebtoken checks these, but they are the two that matter most here, and a
        // future change to `validation` should not be able to silently drop them.
        if data.claims.iss != ISSUER {
            bail!("unexpected issuer {}", data.claims.iss);
        }
        if data.claims.aud != self.audience {
            bail!("token was issued for a different site");
        }
        Ok(data.claims)
    }
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
    fn audience_is_the_prefixed_origin() {
        // Shoo derives client_id as "origin:" + origin, and stamps that into `aud`.
        let verifier = ShooVerifier::new("https://dev.site");
        assert_eq!(verifier.audience(), "origin:https://dev.site");
        // A trailing slash must not produce a different audience string.
        assert_eq!(
            ShooVerifier::new("https://dev.site/").audience(),
            "origin:https://dev.site"
        );
    }

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
