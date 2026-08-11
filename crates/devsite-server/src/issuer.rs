//! The control plane's capability-signing key.
//!
//! This key is the root of trust for every daemon. Daemons pin its public half at login
//! and refuse anything not signed by it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use devsite_proto::capability::{
    CapabilityClaims, KeyBytes, Permission, SignedCapability, DEFAULT_LIFETIME_SECS,
};
use devsite_proto::{AccountId, ResourceId};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub struct Issuer {
    issuer_name: String,
    key: SigningKey,
}

impl Issuer {
    /// Load a signing key supplied directly, as 64 hex characters.
    ///
    /// For hosts where the filesystem is the wrong place to keep it. On Fly the
    /// key is a secret: encrypted at rest, injected into the machine's
    /// environment, and — the part that matters — not tied to the survival of one
    /// volume on one host. Losing this key is the single unrecoverable failure in
    /// the system, because every daemon pinned its public half at `devsite login`
    /// and refuses capabilities signed by anything else.
    ///
    /// An unusable value is an error, never a fallback to generating a fresh key:
    /// that would break every daemon in the field while looking perfectly healthy
    /// from here.
    pub fn from_hex(hex: &str, issuer_name: &str) -> Result<Self> {
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .context("the signing key is not hex")?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("the signing key is not 32 bytes"))?;
        Ok(Self {
            issuer_name: issuer_name.to_string(),
            key: SigningKey::from_bytes(&bytes),
        })
    }

    /// Load the signing key from the state directory, generating it on first run.
    pub fn load_or_create(state_dir: &Path, issuer_name: &str) -> Result<Self> {
        let path = state_dir.join("capability_signing.key");
        let key = if path.exists() {
            let raw = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} is not a 32 byte key", path.display()))?;
            SigningKey::from_bytes(&bytes)
        } else {
            std::fs::create_dir_all(state_dir)?;
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            write_private(&path, &key.to_bytes())?;
            tracing::info!("generated a new capability signing key at {}", path.display());
            key
        };
        Ok(Self {
            issuer_name: issuer_name.to_string(),
            key,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Hex-encoded public key, as daemons pin it.
    pub fn public_key_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(self.verifying_key().as_bytes())
    }

    /// Mint a grant. Every field is supplied by the caller from verified state — nothing
    /// here comes from the browser except `browser_key`, which is exactly what the daemon
    /// will check the connection against.
    pub fn issue(
        &self,
        viewer: AccountId,
        resource: ResourceId,
        audience: KeyBytes,
        browser_key: KeyBytes,
        now: u64,
    ) -> Result<SignedCapability> {
        let mut nonce = [0u8; 16];
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);
        }
        let claims = CapabilityClaims {
            issuer: self.issuer_name.clone(),
            viewer,
            resource,
            audience,
            browser_key,
            permission: Permission::HttpRead,
            issued_at: now,
            expires_at: now + DEFAULT_LIFETIME_SECS,
            nonce,
        };
        SignedCapability::sign(&claims, &self.key).map_err(|err| anyhow::anyhow!("{err}"))
    }
}

fn write_private(path: &PathBuf, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_capabilities_verify_and_expire() {
        let dir = std::env::temp_dir().join(format!("devsite-issuer-{}", std::process::id()));
        let issuer = Issuer::load_or_create(&dir, "https://dev.site").unwrap();

        let cap = issuer
            .issue(
                AccountId::from_bytes([1; 16]),
                ResourceId::from_bytes([2; 16]),
                [7; 32],
                [8; 32],
                1000,
            )
            .unwrap();

        assert!(cap
            .verify_for(&issuer.verifying_key(), &[7; 32], &[8; 32], 1000)
            .is_ok());
        assert!(cap
            .verify_for(&issuer.verifying_key(), &[7; 32], &[8; 32], 1000 + DEFAULT_LIFETIME_SECS + 1)
            .is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_supplied_key_is_used_verbatim() {
        // The same 32 bytes must always yield the same public half, whether they
        // arrived from a file or from a secret: a deployment that moves hosts
        // keeps its identity only if this holds.
        let hex = data_encoding::HEXLOWER.encode(&[9u8; 32]);
        let from_secret = Issuer::from_hex(&hex, "https://dev.site").unwrap();
        let expected = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert_eq!(
            from_secret.public_key_hex(),
            data_encoding::HEXLOWER.encode(expected.as_bytes())
        );
        // Uppercase and stray whitespace are what a shell pipeline produces.
        assert_eq!(
            Issuer::from_hex(&format!("  {}\n", hex.to_uppercase()), "https://dev.site")
                .unwrap()
                .public_key_hex(),
            from_secret.public_key_hex()
        );
    }

    #[test]
    fn an_unusable_supplied_key_is_refused_rather_than_replaced() {
        for bad in ["", "not-hex", &"ab".repeat(31), &"ab".repeat(33)] {
            assert!(
                Issuer::from_hex(bad, "https://dev.site").is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn the_key_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("devsite-issuer-p-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();

        let first = Issuer::load_or_create(&dir, "https://dev.site").unwrap();
        let second = Issuer::load_or_create(&dir, "https://dev.site").unwrap();
        // Daemons pin this key. If it changed on restart, every daemon in the world would
        // start rejecting valid capabilities.
        assert_eq!(first.public_key_hex(), second.public_key_hex());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn each_capability_gets_a_distinct_nonce() {
        let dir = std::env::temp_dir().join(format!("devsite-issuer-n-{}", std::process::id()));
        let issuer = Issuer::load_or_create(&dir, "https://dev.site").unwrap();
        let mint = || {
            issuer
                .issue(
                    AccountId::from_bytes([1; 16]),
                    ResourceId::from_bytes([2; 16]),
                    [7; 32],
                    [8; 32],
                    1000,
                )
                .unwrap()
                .verify(&issuer.verifying_key())
                .unwrap()
                .nonce
        };
        // Identical inputs must still produce distinct grants, or the daemon's replay
        // guard would reject a viewer's second legitimate visit.
        assert_ne!(mint(), mint());
        std::fs::remove_dir_all(&dir).ok();
    }
}
