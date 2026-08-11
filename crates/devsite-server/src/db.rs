//! SQLite storage for the control plane.
//!
//! The control plane stores metadata and permissions. It never stores or sees the contents
//! of a private service — that traffic goes browser-to-daemon over the relay.

use std::str::FromStr;

use anyhow::{Context, Result};
use devsite_proto::{AccountId, ResourceId};
use rusqlite::{params, Connection, OptionalExtension};

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
    // Presence is gone, and with it the 15-second heartbeat that maintained these
    // three columns. A daemon's endpoint id is derived from its secret key and
    // never changes, so it is registered once; its address is published by the
    // daemon itself through iroh's address lookup and resolved by the browser,
    // which is why the control plane no longer stores a relay url. What remains
    // is the identity a capability is addressed to.
    "ALTER TABLE daemons DROP COLUMN relay_url;
     ALTER TABLE daemons DROP COLUMN serving;
     ALTER TABLE daemons DROP COLUMN last_seen;",
    // Folders. Deliberately a name on the resource rather than a table of its
    // own: a folder then exists exactly as long as something is in it. Nothing
    // to create, nothing to delete, no way to be left holding an empty one, and
    // renaming is retagging.
    "ALTER TABLE resources ADD COLUMN folder TEXT;",
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
    /// The folder it sits in, if any. A folder is just this name repeated across
    /// the resources that share it.
    pub folder: Option<String>,
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

/// Connection settings, applied on every open.
///
/// `foreign_keys` is per-connection and defaults to off, so setting it inside
/// `SCHEMA` only ever covered the connection that created the database — every
/// later process ran with `ON DELETE CASCADE` silently doing nothing. It belongs
/// here, where it runs each time.
///
/// The rest is about being killed rather than asked to stop, which is the normal
/// way a process ends on a host that redeploys by replacing the machine. WAL
/// keeps readers off the writer's back and survives an abrupt exit by replaying
/// the log; `synchronous = NORMAL` is the documented companion to it, trading a
/// fsync per commit for one per checkpoint. A crash can then lose the last
/// transactions, which for this data means a profile edit someone can redo — not
/// a corrupt database.
fn configure(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;",
    )
    .context("configuring the database connection")
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening database {path}"))?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure(&conn)?;
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
        folder: Option<&str>,
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
                "UPDATE resources SET visibility = ?1, url = ?2, folder = ?3 WHERE id = ?4",
                params![visibility.as_str(), url, folder, id.to_string()],
            )?;
            return Ok(id);
        }

        let id = ResourceId::generate();
        self.conn.execute(
            "INSERT INTO resources (id, owner_id, name, kind, visibility, url, folder, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id.to_string(),
                owner.to_string(),
                name,
                kind.as_str(),
                visibility.as_str(),
                url,
                folder,
                now as i64
            ],
        )?;
        Ok(id)
    }

    pub fn resource(&self, id: ResourceId) -> Result<Option<Resource>> {
        self.conn
            .query_row(
                "SELECT id, owner_id, name, kind, visibility, url, folder FROM resources WHERE id = ?1",
                params![id.to_string()],
                row_to_resource,
            )
            .optional()?
            .transpose()
    }

    pub fn resources_owned_by(&self, owner: AccountId) -> Result<Vec<Resource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, owner_id, name, kind, visibility, url, folder FROM resources
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
            "SELECT r.id, r.owner_id, r.name, r.kind, r.visibility, r.url, r.folder
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

    /// Set exactly who a resource is shared with, replacing whoever was there.
    ///
    /// Replacing rather than adding is the whole point. `devsite expose --share
    /// @carol` reads as "this is Carol's now", and an accumulating list would
    /// leave everyone previously named still holding access — a permission that
    /// could be granted and never taken back. Sharing with nobody revokes.
    pub fn set_shares(&mut self, resource: ResourceId, viewers: &[AccountId]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM shares WHERE resource_id = ?1",
            params![resource.to_string()],
        )?;
        for viewer in viewers {
            tx.execute(
                "INSERT OR IGNORE INTO shares (resource_id, viewer_id) VALUES (?1, ?2)",
                params![resource.to_string(), viewer.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete a resource, and with it every share of it.
    ///
    /// Scoped by owner in the statement itself rather than checked beforehand,
    /// so a request naming someone else's resource deletes nothing rather than
    /// relying on a caller to have asked the right question first. The shares go
    /// by `ON DELETE CASCADE`, which only works because `foreign_keys` is now set
    /// on every connection.
    ///
    /// Returns whether anything was deleted.
    pub fn delete_resource(&self, owner: AccountId, resource: ResourceId) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM resources WHERE id = ?1 AND owner_id = ?2",
            params![resource.to_string(), owner.to_string()],
        )?;
        Ok(rows > 0)
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

    // -- profiles ---------------------------------------------------------------

    /// The account's stored theme, as the canonical declaration text written by
    /// `crate::theme::to_css`. Nothing else is ever written to this column.
    pub fn custom_css(&self, account: AccountId) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT custom_css FROM profiles WHERE account_id = ?1",
                params![account.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .filter(|css| !css.trim().is_empty()))
    }

    /// Replace the account's theme. `None` clears it.
    ///
    /// Upserts because the profile row is created when a handle is claimed, and
    /// an account that predates that is still allowed to have a theme.
    pub fn set_custom_css(&self, account: AccountId, css: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO profiles (account_id, custom_css) VALUES (?1, ?2)
             ON CONFLICT(account_id) DO UPDATE SET custom_css = excluded.custom_css",
            params![account.to_string(), css],
        )?;
        Ok(())
    }

    // -- daemon identity --------------------------------------------------------

    /// Record which endpoint id an account's daemon answers on.
    ///
    /// Written once, when a daemon starts, rather than on a timer: the id is the
    /// public half of the key at `DEVSITE_HOME/identity`, so it survives restarts
    /// and only changes if that file does. It says nothing about whether the
    /// daemon is running — only who to address a capability to, and who the
    /// browser should go looking for.
    pub fn register_daemon(&self, account: AccountId, endpoint_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO daemons (account_id, endpoint_id) VALUES (?1, ?2)
             ON CONFLICT(account_id) DO UPDATE SET endpoint_id = excluded.endpoint_id",
            params![account.to_string(), endpoint_id],
        )?;
        Ok(())
    }

    pub fn daemon_endpoint(&self, account: AccountId) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT endpoint_id FROM daemons WHERE account_id = ?1",
                params![account.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
    }
}

fn row_to_resource(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Resource>> {
    let id: String = row.get(0)?;
    let owner: String = row.get(1)?;
    let name: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let visibility: String = row.get(4)?;
    let url: Option<String> = row.get(5)?;
    let folder: Option<String> = row.get(6)?;

    Ok((|| {
        Ok(Resource {
            id: ResourceId::from_str(&id)?,
            owner_id: AccountId::from_str(&owner)?,
            name,
            kind: ResourceKind::parse(&kind).context("unknown resource kind")?,
            visibility: Visibility::parse(&visibility).context("unknown visibility")?,
            url,
            folder,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> (Db, Account, Account) {
        let db = Db::open_in_memory().unwrap();
        let alice = db.upsert_account("ps_alice", 0).unwrap();
        let bob = db.upsert_account("ps_bob", 0).unwrap();
        db.set_handle(alice.id, "alice").unwrap();
        db.set_handle(bob.id, "bob").unwrap();
        (db, alice, bob)
    }

    #[test]
    fn signing_in_twice_reuses_the_same_account() {
        let db = Db::open_in_memory().unwrap();
        let first = db.upsert_account("ps_alice", 0).unwrap();
        let second = db.upsert_account("ps_alice", 100).unwrap();
        assert_eq!(first.id, second.id, "a returning user must not get a new account");
    }

    #[test]
    fn re_sharing_replaces_the_list_rather_than_adding_to_it() {
        // The bug this exists to prevent: `expose --share @carol` reading as
        // "and Carol too". A share that can be granted and never revoked is not
        // a share, it is a one-way door.
        let (mut db, alice, bob) = seeded();
        let carol = db.upsert_account("ps_carol", 0).unwrap();
        db.set_handle(carol.id, "carol").unwrap();

        let agent = db
            .create_resource(alice.id, "Agent", ResourceKind::Service, Visibility::Shared, None, None, 0)
            .unwrap();

        db.set_shares(agent, &[bob.id]).unwrap();
        assert_eq!(db.shared_with(agent).unwrap(), vec![bob.id]);

        db.set_shares(agent, &[carol.id]).unwrap();
        assert_eq!(
            db.shared_with(agent).unwrap(),
            vec![carol.id],
            "Bob should have lost access, not kept it alongside Carol"
        );

        // Sharing with nobody is how you take it back entirely.
        db.set_shares(agent, &[]).unwrap();
        assert!(db.shared_with(agent).unwrap().is_empty());
        assert!(db.resources_shared_with(carol.id).unwrap().is_empty());
    }

    #[test]
    fn a_folder_is_set_replaced_and_cleared_by_naming_it_or_not() {
        // A folder has no independent existence — it is this string on however
        // many resources carry it — so re-adding without one takes the resource
        // out of it, the same way re-sharing without a handle revokes.
        let (db, alice, _) = seeded();

        let id = db
            .create_resource(alice.id, "klot.ski", ResourceKind::Link, Visibility::Public,
                             Some("https://klot.ski"), Some("Games"), 0)
            .unwrap();
        assert_eq!(db.resource(id).unwrap().unwrap().folder.as_deref(), Some("Games"));

        let same = db
            .create_resource(alice.id, "klot.ski", ResourceKind::Link, Visibility::Public,
                             Some("https://klot.ski"), Some("Toys"), 0)
            .unwrap();
        assert_eq!(same, id, "re-adding must not make a second entry");
        assert_eq!(db.resource(id).unwrap().unwrap().folder.as_deref(), Some("Toys"));

        db.create_resource(alice.id, "klot.ski", ResourceKind::Link, Visibility::Public,
                           Some("https://klot.ski"), None, 0)
            .unwrap();
        assert!(
            db.resource(id).unwrap().unwrap().folder.is_none(),
            "naming no folder should take it out of the one it was in"
        );
    }

    #[test]
    fn deleting_a_resource_takes_its_shares_with_it() {
        let (mut db, alice, bob) = seeded();
        let agent = db
            .create_resource(alice.id, "Agent", ResourceKind::Service, Visibility::Shared, None, None, 0)
            .unwrap();
        db.set_shares(agent, &[bob.id]).unwrap();

        assert!(db.delete_resource(alice.id, agent).unwrap());
        assert!(db.resource(agent).unwrap().is_none());
        assert!(
            db.shared_with(agent).unwrap().is_empty(),
            "the share should have cascaded away with the resource"
        );
        assert!(db.resources_shared_with(bob.id).unwrap().is_empty());
        // Deleting it twice is not an error, it is just nothing.
        assert!(!db.delete_resource(alice.id, agent).unwrap());
    }

    #[test]
    fn you_can_only_delete_your_own_resources() {
        let (mut db, alice, bob) = seeded();
        let hermes = db
            .create_resource(alice.id, "Hermes", ResourceKind::Service, Visibility::Shared, None, None, 0)
            .unwrap();
        // Shared with Bob, so he can see it — which must not extend to removing it.
        db.set_shares(hermes, &[bob.id]).unwrap();

        assert!(!db.delete_resource(bob.id, hermes).unwrap());
        assert!(db.resource(hermes).unwrap().is_some());
    }

    #[test]
    fn shares_are_visible_to_the_named_viewer_only() {
        let (mut db, alice, bob) = seeded();
        let agent = db
            .create_resource(alice.id, "Agent", ResourceKind::Service, Visibility::Shared, None, None, 0)
            .unwrap();
        let hermes = db
            .create_resource(alice.id, "Hermes", ResourceKind::Service, Visibility::Private, None, None, 0)
            .unwrap();
        db.set_shares(agent, &[bob.id]).unwrap();

        let bobs = db.resources_shared_with(bob.id).unwrap();
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].id, agent);
        assert!(
            !bobs.iter().any(|r| r.id == hermes),
            "a private resource must never appear in someone else's shared list"
        );
    }

    #[test]
    fn owners_do_not_see_their_own_resources_as_shared_with_them() {
        let (mut db, alice, bob) = seeded();
        let agent = db
            .create_resource(alice.id, "Agent", ResourceKind::Service, Visibility::Shared, None, None, 0)
            .unwrap();
        db.set_shares(agent, &[bob.id, alice.id]).unwrap();
        assert!(
            db.resources_shared_with(alice.id).unwrap().is_empty(),
            "own resources belong in the profile list, not `shared with me`"
        );
    }

    #[test]
    fn expired_sessions_do_not_resolve() {
        let (db, alice, _) = seeded();
        db.create_session("hash", alice.id, 100).unwrap();
        assert!(db.session_account("hash", 50).unwrap().is_some());
        assert!(db.session_account("hash", 100).unwrap().is_none());
        assert!(db.session_account("hash", 500).unwrap().is_none());
    }

    #[test]
    fn registering_a_daemon_is_idempotent_and_survives_re_registration() {
        let (db, alice, _) = seeded();
        assert!(db.daemon_endpoint(alice.id).unwrap().is_none());

        db.register_daemon(alice.id, "abc").unwrap();
        db.register_daemon(alice.id, "abc").unwrap();
        assert_eq!(db.daemon_endpoint(alice.id).unwrap().as_deref(), Some("abc"));

        // A new identity file means a new endpoint id, and the account should
        // follow it rather than keeping an id nothing answers on.
        db.register_daemon(alice.id, "def").unwrap();
        assert_eq!(db.daemon_endpoint(alice.id).unwrap().as_deref(), Some("def"));
    }

    #[test]
    fn migrations_reach_a_database_created_before_they_existed() {
        // Simulates the real failure: a database built from an older schema, then opened
        // by a newer binary. Without migrations the new column is silently absent and
        // every read of it fails at runtime.
        //
        // It now covers the other direction too. Removing presence dropped three
        // columns, and a database old enough to still have them — with a
        // heartbeat's worth of data in them — has to survive being opened.
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
        let legacy_account = AccountId::generate().to_string();
        legacy
            .execute(
                "INSERT INTO accounts (id, external_sub, handle, created_at)
                 VALUES (?1, 'ps_x', 'alice', 0)",
                params![legacy_account],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO daemons (account_id, endpoint_id, relay_url, last_seen)
                 VALUES (?1, 'abc', 'https://relay.example/', 100)",
                params![legacy_account],
            )
            .unwrap();
        drop(legacy);

        let db = Db::open(file.to_str().unwrap()).unwrap();
        let alice = db.account_by_handle("alice").unwrap().unwrap();

        // The identity survives the columns around it being dropped: an existing
        // daemon keeps working without re-registering.
        assert_eq!(db.daemon_endpoint(alice.id).unwrap().as_deref(), Some("abc"));

        std::fs::remove_file(&file).ok();
    }

    #[test]
    fn re_exposing_a_service_keeps_its_id_and_updates_it() {
        // `devsite expose --name Hermes` run twice must not leave two Hermes entries on
        // the profile, and the id must survive so already-issued capabilities still name
        // the same thing.
        let (db, alice, _) = seeded();
        let first = db
            .create_resource(alice.id, "Hermes", ResourceKind::Service, Visibility::Private, None, None, 0)
            .unwrap();
        let second = db
            .create_resource(alice.id, "Hermes", ResourceKind::Service, Visibility::Shared, None, None, 10)
            .unwrap();

        assert_eq!(first, second, "re-exposing must reuse the resource id");
        let owned = db.resources_owned_by(alice.id).unwrap();
        assert_eq!(owned.len(), 1, "expected exactly one Hermes, got {owned:?}");
        assert_eq!(owned[0].visibility, Visibility::Shared, "visibility should update");
    }

    #[test]
    fn different_people_may_use_the_same_service_name() {
        let (db, alice, bob) = seeded();
        let a = db
            .create_resource(alice.id, "Agent", ResourceKind::Service, Visibility::Private, None, None, 0)
            .unwrap();
        let b = db
            .create_resource(bob.id, "Agent", ResourceKind::Service, Visibility::Private, None, None, 0)
            .unwrap();
        assert_ne!(a, b, "names are scoped to their owner");
    }

    #[test]
    fn foreign_keys_are_enforced_on_every_connection() {
        // Not a hypothetical: the pragma lived in SCHEMA, which migrations skip
        // for an existing database, so every process after the first ran without
        // it. A share pointing at a deleted resource would have been left behind.
        let (mut db, alice, bob) = seeded();
        let agent = db
            .create_resource(alice.id, "Agent", ResourceKind::Service, Visibility::Shared, None, None, 0)
            .unwrap();
        db.set_shares(agent, &[bob.id]).unwrap();

        db.conn
            .execute("DELETE FROM resources WHERE id = ?1", params![agent.to_string()])
            .unwrap();

        assert!(
            db.resources_shared_with(bob.id).unwrap().is_empty(),
            "the share should have been cascaded away with its resource"
        );
    }

    #[test]
    fn a_theme_round_trips_and_can_be_cleared() {
        let (db, alice, _) = seeded();
        assert!(db.custom_css(alice.id).unwrap().is_none());

        db.set_custom_css(alice.id, Some("--pico-primary: #7b3fe4;\n")).unwrap();
        assert_eq!(
            db.custom_css(alice.id).unwrap().as_deref(),
            Some("--pico-primary: #7b3fe4;\n")
        );

        db.set_custom_css(alice.id, None).unwrap();
        assert!(db.custom_css(alice.id).unwrap().is_none());
    }

    #[test]
    fn handles_are_matched_case_insensitively() {
        let (db, alice, _) = seeded();
        assert_eq!(db.account_by_handle("AlIcE").unwrap().unwrap().id, alice.id);
    }
}
