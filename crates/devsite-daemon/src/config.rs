//! Daemon state: its identity, the control plane it trusts, and the resources it serves.
//!
//! The resource map is the security boundary that keeps the daemon from being an open
//! proxy. A capability names a *resource id*; only this map turns that into a TCP target, and
//! it is written exclusively by the local `devsite` CLI.

use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
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
pub struct HostedService {
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
    /// for registering this daemon's endpoint id when it starts.
    #[serde(default)]
    pub machine_credential: Option<String>,
    /// The control plane's capability-signing public key, pinned at login.
    ///
    /// Hex-encoded. A daemon that has not pinned a key cannot verify anything and refuses
    /// every request, which is the correct failure direction.
    pub control_plane_key: Option<String>,
    #[serde(default)]
    pub resources: Vec<HostedService>,
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

/// An exclusive claim that this config directory has one daemon serving it.
///
/// The operating system releases the lock when the process exits, including
/// crashes, so there is no stale PID file to clean up or trust.
pub struct DaemonLock {
    _file: File,
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

    /// Public half of [`Self::identity`]. Public Ed25519 material follows the
    /// conventional `.pub` naming used by the rest of the CLI handoff files.
    pub fn identity_public(&self) -> PathBuf {
        self.root.join("identity.pub")
    }

    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn daemon_lock(&self) -> PathBuf {
        self.root.join("daemon.lock")
    }

    /// Try to become the daemon for this config directory.
    ///
    /// `None` means another process currently owns the lock. Keeping the
    /// returned guard alive keeps the claim; dropping it releases the claim.
    pub fn try_daemon_lock(&self) -> Result<Option<DaemonLock>> {
        std::fs::create_dir_all(&self.root)?;
        let path = self.daemon_lock();
        let file = open_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(DaemonLock { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(err)) => {
                Err(err).with_context(|| format!("locking {}", path.display()))
            }
        }
    }

    /// Whether a daemon currently owns this config directory.
    pub fn daemon_running(&self) -> Result<bool> {
        if !self.daemon_lock().exists() {
            return Ok(false);
        }
        Ok(self.try_daemon_lock()?.is_none())
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
        let key = if path.exists() {
            let raw =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} is not a 32 byte key", path.display()))?;
            SecretKey::from_bytes(&bytes)
        } else {
            std::fs::create_dir_all(&self.root)?;
            let key = SecretKey::generate();
            write_private(&path, &key.to_bytes())?;
            key
        };

        let public = format!("{}\n", key.public());
        let public_path = self.identity_public();
        if std::fs::read_to_string(&public_path).ok().as_deref() != Some(public.as_str()) {
            std::fs::write(&public_path, public.as_bytes())
                .with_context(|| format!("writing {}", public_path.display()))?;
        }
        Ok(key)
    }
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

    fn test_paths() -> Paths {
        let suffix = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        Paths {
            root: std::env::temp_dir().join(format!(
                "devsite-daemon-lock-{}-{suffix}",
                std::process::id()
            )),
        }
    }

    #[test]
    fn daemon_lock_reports_only_a_live_holder() {
        let paths = test_paths();
        assert!(!paths.daemon_running().unwrap());

        let lock = paths.try_daemon_lock().unwrap().unwrap();
        assert!(paths.daemon_running().unwrap());
        assert!(paths.try_daemon_lock().unwrap().is_none());

        drop(lock);
        assert!(!paths.daemon_running().unwrap());
        std::fs::remove_dir_all(&paths.root).unwrap();
    }

    #[test]
    fn identity_writes_its_public_half_as_a_pub_file() {
        let paths = test_paths();
        let key = paths.load_or_create_identity().unwrap();

        assert_eq!(
            std::fs::read_to_string(paths.identity_public()).unwrap(),
            format!("{}\n", key.public())
        );

        std::fs::remove_dir_all(&paths.root).unwrap();
    }
}
