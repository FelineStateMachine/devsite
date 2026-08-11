//! SQLite storage for the control plane.
//!
//! The control plane stores metadata and permissions. It never stores or sees the contents
//! of a private service — that traffic goes browser-to-daemon over the relay.

use std::str::FromStr;

use anyhow::{Context, Result};
use devsite_proto::{AccountId, ResourceId};
use rusqlite::{params, Connection, OptionalExtension};
use url::Url;

use crate::policy::Visibility;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id           TEXT PRIMARY KEY,
    -- Shoo's pairwise subject. Unique per (user, origin), so it is stable for us but
    -- cannot be correlated with the same user on another site.
    external_sub TEXT NOT NULL UNIQUE,
    handle       TEXT UNIQUE,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    -- Only a hash is stored: a leaked database does not yield usable session tokens.
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('link', 'service')),
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private', 'shared')),
    -- Set for links (the external URL). Always NULL for services: the local origin lives
    -- only in the owner's daemon config and is never uploaded here.
    url        TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    viewer_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (resource_id, viewer_id)
);

CREATE TABLE IF NOT EXISTS daemons (
    account_id  TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL,
    relay_url   TEXT NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    bio        TEXT,
    -- Reserved for user-authored CSS. Unused for now; the point is that customization
    -- will be real CSS rather than a theme dropdown.
    custom_css TEXT
);
"#;

/// Schema changes, applied in order and tracked in `PRAGMA user_version`.
///
/// Append only — never edit an entry that has shipped. `CREATE TABLE IF NOT EXISTS` alone
/// is not schema evolution: it silently does nothing when the table already exists, so a
/// column added to the block above would never reach an existing database.
const MIGRATIONS: &[&str] = &[
    SCHEMA,
    // JSON array of the resource ids a daemon is actually configured to serve, so a
    // resource can be reported reachable only if its owner's daemon still exposes it.
    "ALTER TABLE daemons ADD COLUMN serving TEXT NOT NULL DEFAULT '[]';",
];

fn migrate(conn: &Connection) -> Result<()> {
    let applied: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied as usize) {
        conn.execute_batch(migration)
            .with_context(|| format!("applying migration {}", index + 1))?;
        conn.pragma_update(None, "user_version", (index + 1) as i64)?;
    }
    Ok(())
}

/// A daemon is considered online if it has checked in this recently.
pub const PRESENCE_WINDOW_SECS: u64 = 45;

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub id: AccountId,
    pub handle: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub id: ResourceId,
    pub owner_id: AccountId,
    pub name: String,
    pub kind: ResourceKind,
    pub visibility: Visibility,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Link,
    Service,
}

impl ResourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceKind::Link => "link",
            ResourceKind::Service => "service",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "link" => Some(ResourceKind::Link),
            "service" => Some(ResourceKind::Service),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DaemonPresence {
    pub endpoint_id: String,
    pub relay_url: Url,
    pub serving: Vec<ResourceId>,
    pub last_seen: u64,
}

impl DaemonPresence {
    /// Whether the daemon itself has checked in recently.
    pub fn is_online(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen) <= PRESENCE_WINDOW_SECS
    }

    /// Whether a specific resource is actually reachable right now.
    pub fn is_serving(&self, resource: ResourceId, now: u64) -> bool {
        self.is_online(now) && self.serving.contains(&resource)
    }
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening database {path}"))?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    // -- accounts ---------------------------------------------------------------

    /// Find the account for an external subject, creating one on first sign-in.
    pub fn upsert_account(&self, external_sub: &str, now: u64) -> Result<Account> {
        if let Some(account) = self.account_by_external_sub(external_sub)? {
            return Ok(account);
        }
        let id = AccountId::generate();
        self.conn.execute(
            "INSERT INTO accounts (id, external_sub, handle, created_at) VALUES (?1, ?2, NULL, ?3)",
            params![id.to_string(), external_sub, now as i64],
        )?;
        Ok(Account { id, handle: None })
    }

    pub fn account_by_external_sub(&self, external_sub: &str) -> Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT id, handle FROM accounts WHERE external_sub = ?1",
                params![external_sub],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .map(|(id, handle)| {
                Ok(Account {
                    id: AccountId::from_str(&id)?,
                    handle,
                })
            })
            .transpose()
    }

    pub fn account_by_id(&self, id: AccountId) -> Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT handle FROM accounts WHERE id = ?1",
                params![id.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map(|opt| opt.map(|handle| Account { id, handle }))
            .map_err(Into::into)
    }

    pub fn account_by_handle(&self, handle: &str) -> Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT id FROM accounts WHERE handle = ?1 COLLATE NOCASE",
                params![handle],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|id| {
                Ok(Account {
                    id: AccountId::from_str(&id)?,
                    handle: Some(handle.to_string()),
                })
            })
            .transpose()
    }

    /// Claim a handle. Fails if it is taken by another account.
    pub fn set_handle(&self, account: AccountId, handle: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE accounts SET handle = ?1 WHERE id = ?2",
                params![handle, account.to_string()],
            )
            .context("that handle is already taken")?;
        self.conn.execute(
            "INSERT OR IGNORE INTO profiles (account_id) VALUES (?1)",
            params![account.to_string()],
        )?;
        Ok(())
    }

    // -- sessions ---------------------------------------------------------------

    pub fn create_session(&self, token_hash: &str, account: AccountId, expires_at: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
            params![token_hash, account.to_string(), expires_at as i64],
        )?;
        Ok(())
    }

    /// Resolve a session token hash to its account, ignoring expired rows.
    pub fn session_account(&self, token_hash: &str, now: u64) -> Result<Option<Account>> {
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT account_id FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash, now as i64],
                |row| row.get(0),
            )
            .optional()?;
        match id {
            Some(id) => self.account_by_id(AccountId::from_str(&id)?),
            None => Ok(None),
        }
    }

    pub fn purge_expired_sessions(&self, now: u64) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now as i64])?;
        Ok(())
    }

    // -- resources --------------------------------------------------------------

    /// Create a resource, or update the one that already has this owner, name and kind.
    ///
    /// Re-running `devsite expose --name Hermes` is an ordinary thing to do — to change
    /// visibility, or to add a share. Inserting each time would leave a duplicate entry on
    /// the profile pointing at a resource id no daemon serves any more. Keeping the id
    /// stable also means capabilities already issued for it stay meaningful.
    #[allow(clippy::too_many_arguments)]
    pub fn create_resource(
        &self,
        owner: AccountId,
        name: &str,
        kind: ResourceKind,
        visibility: Visibility,
        url: Option<&str>,
        now: u64,
    ) -> Result<ResourceId> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM resources WHERE owner_id = ?1 AND name = ?2 AND kind = ?3",
                params![owner.to_string(), name, kind.as_str()],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            let id = ResourceId::from_str(&id)?;
            self.conn.execute(
                "UPDATE resources SET visibility = ?1, url = ?2 WHERE id = ?3",
                params![visibility.as_str(), url, id.to_string()],
            )?;
            return Ok(id);
        }

        let id = ResourceId::generate();
        self.conn.execute(
            "INSERT INTO resources (id, owner_id, name, kind, visibility, url, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id.to_string(),
                owner.to_string(),
                name,
                kind.as_str(),
                visibility.as_str(),
                url,
                now as i64
            ],
        )?;
        Ok(id)
    }

    pub fn resource(&self, id: ResourceId) -> Result<Option<Resource>> {
        self.conn
            .query_row(
                "SELECT id, owner_id, name, kind, visibility, url FROM resources WHERE id = ?1",
                params![id.to_string()],
                row_to_resource,
            )
            .optional()?
            .transpose()
    }

    pub fn resources_owned_by(&self, owner: AccountId) -> Result<Vec<Resource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, owner_id, name, kind, visibility, url FROM resources
             WHERE owner_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map(params![owner.to_string()], row_to_resource)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().collect()
    }

    /// Resources belonging to other people that were explicitly shared with `viewer`.
    pub fn resources_shared_with(&self, viewer: AccountId) -> Result<Vec<Resource>> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.owner_id, r.name, r.kind, r.visibility, r.url
             FROM resources r
             JOIN shares s ON s.resource_id = r.id
             WHERE s.viewer_id = ?1 AND r.owner_id != ?1
             ORDER BY r.created_at",
        )?;
        let rows = stmt
            .query_map(params![viewer.to_string()], row_to_resource)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().collect()
    }

    pub fn share_with(&self, resource: ResourceId, viewer: AccountId) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO shares (resource_id, viewer_id) VALUES (?1, ?2)",
            params![resource.to_string(), viewer.to_string()],
        )?;
        Ok(())
    }

    pub fn shared_with(&self, resource: ResourceId) -> Result<Vec<AccountId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT viewer_id FROM shares WHERE resource_id = ?1")?;
        let rows = stmt
            .query_map(params![resource.to_string()], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter()
            .map(|id| AccountId::from_str(id).map_err(Into::into))
            .collect()
    }

    // -- daemon presence --------------------------------------------------------

    pub fn record_heartbeat(
        &self,
        account: AccountId,
        endpoint_id: &str,
        relay_url: &str,
        serving: &[ResourceId],
        now: u64,
    ) -> Result<()> {
        let serving = serde_json::to_string(
            &serving.iter().map(ToString::to_string).collect::<Vec<_>>(),
        )?;
        self.conn.execute(
            "INSERT INTO daemons (account_id, endpoint_id, relay_url, serving, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(account_id) DO UPDATE SET
                endpoint_id = excluded.endpoint_id,
                relay_url = excluded.relay_url,
                serving = excluded.serving,
                last_seen = excluded.last_seen",
            params![account.to_string(), endpoint_id, relay_url, serving, now as i64],
        )?;
        Ok(())
    }

    pub fn daemon(&self, account: AccountId) -> Result<Option<DaemonPresence>> {
        self.conn
            .query_row(
                "SELECT endpoint_id, relay_url, serving, last_seen FROM daemons
                 WHERE account_id = ?1",
                params![account.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(endpoint_id, relay_url, serving, last_seen)| {
                let serving: Vec<String> = serde_json::from_str(&serving).unwrap_or_default();
                Ok(DaemonPresence {
                    endpoint_id,
                    relay_url: Url::parse(&relay_url)?,
                    serving: serving
                        .iter()
                        .filter_map(|id| ResourceId::from_str(id).ok())
                        .collect(),
                    last_seen: last_seen as u64,
                })
            })
            .transpose()
    }
}

fn row_to_resource(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Resource>> {
    let id: String = row.get(0)?;
    let owner: String = row.get(1)?;
    let name: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let visibility: String = row.get(4)?;
    let url: Option<String> = row.get(5)?;

    Ok((|| {
        Ok(Resource {
            id: ResourceId::from_str(&id)?,
            owner_id: AccountId::from_str(&owner)?,
            name,
            kind: ResourceKind::parse(&kind).context("unknown resource kind")?,
            visibility: Visibility::parse(&visibility).context("unknown visibility")?,
            url,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> (Db, Account, Account) {
        let db = Db::open_in_memory().unwrap();
        let dami = db.upsert_account("ps_dami", 0).unwrap();
        let frank = db.upsert_account("ps_frank", 0).unwrap();
        db.set_handle(dami.id, "dami").unwrap();
        db.set_handle(frank.id, "frank").unwrap();
        (db, dami, frank)
    }

    #[test]
    fn signing_in_twice_reuses_the_same_account() {
        let db = Db::open_in_memory().unwrap();
        let first = db.upsert_account("ps_dami", 0).unwrap();
        let second = db.upsert_account("ps_dami", 100).unwrap();
        assert_eq!(first.id, second.id, "a returning user must not get a new account");
    }

    #[test]
    fn shares_are_visible_to_the_named_viewer_only() {
        let (db, dami, frank) = seeded();
        let agent = db
            .create_resource(dami.id, "Agent", ResourceKind::Service, Visibility::Shared, None, 0)
            .unwrap();
        let hermes = db
            .create_resource(dami.id, "Hermes", ResourceKind::Service, Visibility::Private, None, 0)
            .unwrap();
        db.share_with(agent, frank.id).unwrap();

        let franks = db.resources_shared_with(frank.id).unwrap();
        assert_eq!(franks.len(), 1);
        assert_eq!(franks[0].id, agent);
        assert!(
            !franks.iter().any(|r| r.id == hermes),
            "a private resource must never appear in someone else's shared list"
        );
    }

    #[test]
    fn owners_do_not_see_their_own_resources_as_shared_with_them() {
        let (db, dami, frank) = seeded();
        let agent = db
            .create_resource(dami.id, "Agent", ResourceKind::Service, Visibility::Shared, None, 0)
            .unwrap();
        db.share_with(agent, frank.id).unwrap();
        db.share_with(agent, dami.id).unwrap();
        assert!(
            db.resources_shared_with(dami.id).unwrap().is_empty(),
            "own resources belong in the profile list, not `shared with me`"
        );
    }

    #[test]
    fn expired_sessions_do_not_resolve() {
        let (db, dami, _) = seeded();
        db.create_session("hash", dami.id, 100).unwrap();
        assert!(db.session_account("hash", 50).unwrap().is_some());
        assert!(db.session_account("hash", 100).unwrap().is_none());
        assert!(db.session_account("hash", 500).unwrap().is_none());
    }

    #[test]
    fn presence_lapses_after_the_window() {
        let (db, dami, _) = seeded();
        let served = ResourceId::generate();
        let dropped = ResourceId::generate();
        db.record_heartbeat(dami.id, "abc", "https://relay.example/", &[served], 1000)
            .unwrap();
        let presence = db.daemon(dami.id).unwrap().unwrap();

        assert!(presence.is_online(1000));
        assert!(presence.is_online(1000 + PRESENCE_WINDOW_SECS));
        assert!(!presence.is_online(1001 + PRESENCE_WINDOW_SECS));

        // Reachability is per resource, not merely per daemon: a live daemon that no
        // longer exposes something must not have it advertised as reachable.
        assert!(presence.is_serving(served, 1000));
        assert!(!presence.is_serving(dropped, 1000));
        assert!(!presence.is_serving(served, 1001 + PRESENCE_WINDOW_SECS));
    }

    #[test]
    fn migrations_reach_a_database_created_before_they_existed() {
        // Simulates the real failure: a database built from an older schema, then opened
        // by a newer binary. Without migrations the new column is silently absent and
        // every read of it fails at runtime.
        let file = std::env::temp_dir().join(format!("devsite-migrate-{}.db", std::process::id()));
        std::fs::remove_file(&file).ok();

        let legacy = Connection::open(&file).unwrap();
        legacy.execute_batch(SCHEMA).unwrap();
        assert_eq!(
            legacy
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "the legacy database should look unmigrated"
        );
        drop(legacy);

        let db = Db::open(file.to_str().unwrap()).unwrap();
        let dami = db.upsert_account("ps_x", 0).unwrap();
        db.set_handle(dami.id, "dami").unwrap();
        let resource = ResourceId::generate();
        db.record_heartbeat(dami.id, "abc", "https://relay.example/", &[resource], 100)
            .unwrap();

        let presence = db.daemon(dami.id).unwrap().unwrap();
        assert!(presence.is_serving(resource, 100));

        std::fs::remove_file(&file).ok();
    }

    #[test]
    fn re_exposing_a_service_keeps_its_id_and_updates_it() {
        // `devsite expose --name Hermes` run twice must not leave two Hermes entries on
        // the profile, and the id must survive so already-issued capabilities still name
        // the same thing.
        let (db, dami, _) = seeded();
        let first = db
            .create_resource(dami.id, "Hermes", ResourceKind::Service, Visibility::Private, None, 0)
            .unwrap();
        let second = db
            .create_resource(dami.id, "Hermes", ResourceKind::Service, Visibility::Shared, None, 10)
            .unwrap();

        assert_eq!(first, second, "re-exposing must reuse the resource id");
        let owned = db.resources_owned_by(dami.id).unwrap();
        assert_eq!(owned.len(), 1, "expected exactly one Hermes, got {owned:?}");
        assert_eq!(owned[0].visibility, Visibility::Shared, "visibility should update");
    }

    #[test]
    fn different_people_may_use_the_same_service_name() {
        let (db, dami, frank) = seeded();
        let a = db
            .create_resource(dami.id, "Agent", ResourceKind::Service, Visibility::Private, None, 0)
            .unwrap();
        let b = db
            .create_resource(frank.id, "Agent", ResourceKind::Service, Visibility::Private, None, 0)
            .unwrap();
        assert_ne!(a, b, "names are scoped to their owner");
    }

    #[test]
    fn handles_are_matched_case_insensitively() {
        let (db, dami, _) = seeded();
        assert_eq!(db.account_by_handle("DaMi").unwrap().unwrap().id, dami.id);
    }
}
