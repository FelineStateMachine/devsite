//! Daemon state: its identity, the control plane it trusts, and the resources it serves.
//!
//! The resource map is the security boundary that keeps the daemon from being an open
//! proxy. A capability names a *resource id*; only this map turns that into a TCP target, and
//! it is written exclusively by the local `devsite` CLI.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use devsite_proto::ResourceId;
use ed25519_dalek::VerifyingKey;
use iroh::SecretKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedResource {
    pub resource_id: ResourceId,
    pub name: String,
    /// Fixed local TCP target. The peer chooses a resource, never an address.
    pub target: SocketAddr,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Base URL of the control plane, e.g. `https://dev.site`.
    pub server_url: Option<String>,
    /// Revocable machine credential from `devsite login`, used for CLI calls and
    /// for registering this daemon's endpoint id when it starts. The alias reads
    /// configs written before machine credentials were introduced.
    #[serde(default, alias = "session_token")]
    pub machine_credential: Option<String>,
    /// The control plane's capability-signing public key, pinned at login.
    ///
    /// Hex-encoded. A daemon that has not pinned a key cannot verify anything and refuses
    /// every request, which is the correct failure direction.
    pub control_plane_key: Option<String>,
    #[serde(default)]
    pub resources: Vec<ExposedResource>,
}

impl DaemonConfig {
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let hex = self
            .control_plane_key
            .as_deref()
            .context("no control plane key pinned — run `devsite login` first")?;
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.as_bytes())
            .context("control plane key is not valid hex")?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("control plane key is not 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).context("control plane key is not a valid ed25519 key")
    }

    /// Resource id to local target. Built fresh on each use so a config reload takes effect.
    pub fn targets(&self) -> HashMap<ResourceId, SocketAddr> {
        self.resources
            .iter()
            .map(|r| (r.resource_id, r.target))
            .collect()
    }
}

/// Where the daemon keeps its identity and configuration.
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn discover() -> Result<Self> {
        // DEVSITE_HOME keeps integration tests (and multiple daemons on one machine) from
        // colliding on a single shared identity.
        if let Ok(custom) = std::env::var("DEVSITE_HOME") {
            return Ok(Self {
                root: PathBuf::from(custom),
            });
        }
        let dirs = directories::ProjectDirs::from("dev", "devsite", "devsite")
            .context("could not determine a config directory")?;
        Ok(Self {
            root: dirs.config_dir().to_path_buf(),
        })
    }

    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.key")
    }

    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn load_config(&self) -> Result<DaemonConfig> {
        let path = self.config();
        if !path.exists() {
            return Ok(DaemonConfig::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save_config(&self, config: &DaemonConfig) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let text = serde_json::to_string_pretty(config)?;
        write_private(&self.config(), text.as_bytes())
    }

    /// Load the persistent endpoint key, creating it on first run.
    ///
    /// This key *is* the daemon's identity — every capability ever issued names it as the
    /// audience — so it must survive restarts and must not be world-readable.
    pub fn load_or_create_identity(&self) -> Result<SecretKey> {
        let path = self.identity();
        if path.exists() {
            let raw =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} is not a 32 byte key", path.display()))?;
            return Ok(SecretKey::from_bytes(&bytes));
        }

        std::fs::create_dir_all(&self.root)?;
        let key = SecretKey::generate();
        write_private(&path, &key.to_bytes())?;
        Ok(key)
    }
}

/// Write a file only the owner can read.
///
/// The mode is set before any bytes land on disk, so the secret is never briefly exposed
/// with default permissions.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.write_all(contents)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pre_machine_credential_configs() {
        let config: DaemonConfig = serde_json::from_str(
            r#"{"session_token":"old-token","control_plane_key":null,"resources":[]}"#,
        )
        .unwrap();
        assert_eq!(config.machine_credential.as_deref(), Some("old-token"));
    }
}
