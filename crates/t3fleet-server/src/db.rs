use std::{path::Path, sync::Mutex};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params};
use t3fleet_protocol::{DEFAULT_SANDBOX_NAME, SandboxActivity, StatusResponse, WakePolicy};
use uuid::Uuid;

pub struct Db(Mutex<Connection>);

pub struct User {
    pub id: String,
    pub username: String,
    pub size: String,
    pub template: Option<String>,
}

pub struct Sandbox {
    pub id: String,
    pub size: String,
    pub template: Option<String>,
    pub preserved_snapshot: Option<String>,
    pub restore_key: Option<String>,
    pub name: String,
    pub boat_id: String,
    pub alias: String,
    pub state: String,
    pub bootstrapped_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub stopped_reason: Option<String>,
    pub last_activity: Option<SandboxActivity>,
}

fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn time_column(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<DateTime<Utc>>> {
    row.get::<_, Option<String>>(index)?
        .map(|value| {
            value.parse().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn user_row(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        size: row.get(2)?,
        template: row.get(3)?,
    })
}

const SANDBOX_COLUMNS: &str = "s.id, s.size, s.template, s.preserved_snapshot, s.restore_key,
    s.name, s.boat_sandbox_id, s.ssh_alias, s.state, s.bootstrapped_at, s.last_activity_at,
    s.stopped_at, s.stopped_reason, s.last_activity_json";

fn sandbox_row(row: &Row<'_>) -> rusqlite::Result<Sandbox> {
    let activity_json: Option<String> = row.get(13)?;
    Ok(Sandbox {
        id: row.get(0)?,
        size: row.get(1)?,
        template: row.get(2)?,
        preserved_snapshot: row.get(3)?,
        restore_key: row.get(4)?,
        name: row.get(5)?,
        boat_id: row.get(6)?,
        alias: row.get(7)?,
        state: row.get(8)?,
        bootstrapped_at: time_column(row, 9)?,
        last_activity_at: time_column(row, 10)?,
        stopped_at: time_column(row, 11)?,
        stopped_reason: row.get(12)?,
        last_activity: activity_json
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok()),
    })
}

impl Sandbox {
    // The reservation keeps an idempotency key even if Boat's create response is lost.
    pub fn provisioned(&self) -> bool {
        !self.boat_id.starts_with("pending:")
    }
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let mut conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS meta(
                key TEXT PRIMARY KEY, value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS users(
                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                sandbox_size TEXT NOT NULL, ssh_public_key TEXT, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sandboxes(
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL DEFAULT 'default',
                boat_sandbox_id TEXT NOT NULL UNIQUE, ssh_alias TEXT NOT NULL UNIQUE,
                size TEXT NOT NULL, state TEXT NOT NULL, bootstrapped_at TEXT,
                last_activity_at TEXT, stopped_at TEXT, stopped_reason TEXT,
                last_activity_json TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                UNIQUE(user_id, name)
             );
             CREATE TABLE IF NOT EXISTS enrollment_tokens(
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
                used_at TEXT, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS api_tokens(
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                device_name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT
             );",
        )?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for (table, column) in [
            ("users", "template"),
            ("sandboxes", "template"),
            ("sandboxes", "preserved_snapshot"),
            ("sandboxes", "restore_key"),
        ] {
            let present: bool = tx.query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)"
                ),
                [column],
                |row| row.get(0),
            )?;
            if !present {
                tx.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"), [])?;
            }
        }
        tx.commit()?;
        Ok(Self(Mutex::new(conn)))
    }

    pub fn admin_hash(&self, candidate: &str) -> rusqlite::Result<(String, bool)> {
        let conn = self.0.lock().unwrap();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('admin_token_hash', ?1)",
            [candidate],
        )? == 1;
        let hash = conn.query_row(
            "SELECT value FROM meta WHERE key = 'admin_token_hash'",
            [],
            |row| row.get(0),
        )?;
        Ok((hash, inserted))
    }

    pub fn create_user(
        &self,
        username: String,
        size: String,
        template: Option<String>,
    ) -> rusqlite::Result<User> {
        let user = User {
            id: Uuid::new_v4().to_string(),
            username,
            size,
            template,
        };
        self.0.lock().unwrap().execute(
            "INSERT INTO users(id, username, sandbox_size, created_at, template) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.id, user.username, user.size, timestamp(Utc::now()), user.template],
        )?;
        Ok(user)
    }

    pub fn user(&self, username: &str) -> rusqlite::Result<Option<User>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, username, sandbox_size, template FROM users WHERE username = ?1",
                [username],
                user_row,
            )
            .optional()
    }

    pub fn users(&self) -> rusqlite::Result<Vec<User>> {
        self.0
            .lock()
            .unwrap()
            .prepare("SELECT id, username, sandbox_size, template FROM users ORDER BY username")?
            .query_map([], user_row)?
            .collect()
    }

    pub fn invite(&self, user: &User, hash: &str, expires: DateTime<Utc>) -> rusqlite::Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO enrollment_tokens(id, user_id, token_hash, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Uuid::new_v4().to_string(),
                user.id,
                hash,
                timestamp(expires),
                timestamp(Utc::now())
            ],
        )?;
        Ok(())
    }

    pub fn enrollment_user(&self, hash: &str) -> rusqlite::Result<Option<User>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT u.id, u.username, u.sandbox_size, u.template FROM users u
             JOIN enrollment_tokens e ON e.user_id = u.id
             WHERE e.token_hash = ?1 AND e.used_at IS NULL AND e.expires_at > ?2",
                params![hash, timestamp(Utc::now())],
                user_row,
            )
            .optional()
    }

    pub fn claim_enrollment(&self, user: &User, hash: &str) -> rusqlite::Result<bool> {
        let changed = self.0.lock().unwrap().execute(
            "UPDATE enrollment_tokens SET used_at = ?1
             WHERE token_hash = ?2 AND user_id = ?3 AND used_at IS NULL AND expires_at > ?1",
            params![timestamp(Utc::now()), hash, user.id],
        )?;
        Ok(changed == 1)
    }

    pub fn finish_enrollment(
        &self,
        user: &User,
        key: &str,
        device: &str,
        api_hash: &str,
    ) -> rusqlite::Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE users SET ssh_public_key = ?1 WHERE id = ?2",
            params![key, user.id],
        )?;
        tx.execute(
            "INSERT INTO api_tokens(id, user_id, device_name, token_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Uuid::new_v4().to_string(),
                user.id,
                device,
                api_hash,
                timestamp(Utc::now())
            ],
        )?;
        tx.commit()
    }

    pub fn api_user(&self, hash: &str) -> rusqlite::Result<Option<User>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT u.id, u.username, u.sandbox_size, u.template FROM users u
             JOIN api_tokens a ON a.user_id = u.id
             WHERE a.token_hash = ?1 AND a.revoked_at IS NULL",
                [hash],
                user_row,
            )
            .optional()
    }

    pub fn touch_api_token(&self, hash: &str) -> rusqlite::Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE api_tokens SET last_used_at = ?1 WHERE token_hash = ?2",
            params![timestamp(Utc::now()), hash],
        )?;
        Ok(())
    }

    pub fn revoke(&self, user: &User) -> rusqlite::Result<usize> {
        self.0.lock().unwrap().execute(
            "UPDATE api_tokens SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
            params![timestamp(Utc::now()), user.id],
        )
    }

    pub fn delete_user(&self, user: &User) -> rusqlite::Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM users WHERE id = ?1", [&user.id])?;
        Ok(())
    }

    pub fn sandbox(&self, user: &User, name: &str) -> rusqlite::Result<Option<Sandbox>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                &format!(
                    "SELECT {SANDBOX_COLUMNS} FROM sandboxes s WHERE s.user_id = ?1 AND s.name = ?2"
                ),
                params![user.id, name],
                sandbox_row,
            )
            .optional()
    }

    pub fn sandbox_by_id(&self, id: &str) -> rusqlite::Result<Option<Sandbox>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes s WHERE s.id = ?1"),
                [id],
                sandbox_row,
            )
            .optional()
    }

    pub fn sandboxes(&self, user: &User) -> rusqlite::Result<Vec<Sandbox>> {
        self.0
            .lock()
            .unwrap()
            .prepare(&format!(
                "SELECT {SANDBOX_COLUMNS} FROM sandboxes s WHERE s.user_id = ?1 ORDER BY s.name"
            ))?
            .query_map([&user.id], sandbox_row)?
            .collect()
    }

    pub fn all_sandboxes(&self) -> rusqlite::Result<Vec<(String, Sandbox)>> {
        self.fleet_sandboxes("")
    }

    pub fn watched_sandboxes(&self) -> rusqlite::Result<Vec<(String, Sandbox)>> {
        self.fleet_sandboxes(
            "WHERE s.state IN ('ready', 'idle', 'running', 'archived', 'archiving', 'stopping')",
        )
    }

    fn fleet_sandboxes(&self, filter: &str) -> rusqlite::Result<Vec<(String, Sandbox)>> {
        self.0
            .lock()
            .unwrap()
            .prepare(&format!(
                "SELECT {SANDBOX_COLUMNS}, u.username FROM sandboxes s
                JOIN users u ON u.id = s.user_id {filter} ORDER BY u.username, s.name"
            ))?
            .query_map([], |row| Ok((row.get(14)?, sandbox_row(row)?)))?
            .collect()
    }

    pub fn reserve_sandbox(
        &self,
        user: &User,
        name: &str,
        size: &str,
        template: Option<&str>,
    ) -> rusqlite::Result<Option<Sandbox>> {
        let id = Uuid::new_v4().to_string();
        let alias = if name == DEFAULT_SANDBOX_NAME {
            format!("t3fleet-{}", user.username)
        } else {
            format!("t3fleet-{}-{name}", user.username)
        };
        let created = self.0.lock().unwrap().execute(
            "INSERT INTO sandboxes(id, user_id, name, boat_sandbox_id, ssh_alias, size, state,
                                   last_activity_at, created_at, updated_at, template)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'provisioning', ?7, ?7, ?7, ?8)
             ON CONFLICT(ssh_alias) DO NOTHING",
            params![
                id,
                user.id,
                name,
                format!("pending:{id}"),
                alias,
                size,
                timestamp(Utc::now()),
                template
            ],
        )?;
        if created == 0 {
            return Ok(None);
        }
        self.sandbox(user, name)
    }

    pub fn delete_sandbox(&self, user: &User, name: &str) -> rusqlite::Result<()> {
        self.0.lock().unwrap().execute(
            "DELETE FROM sandboxes WHERE user_id = ?1 AND name = ?2",
            params![user.id, name],
        )?;
        Ok(())
    }

    pub fn save_sandbox(&self, sandbox: &Sandbox) -> rusqlite::Result<()> {
        let activity_json = sandbox
            .last_activity
            .as_ref()
            .and_then(|activity| serde_json::to_string(activity).ok());
        self.0.lock().unwrap().execute(
            "UPDATE sandboxes SET state = ?1, bootstrapped_at = ?2, last_activity_at = ?3,
                    stopped_at = ?4, stopped_reason = ?5, last_activity_json = ?6, updated_at = ?7,
                    boat_sandbox_id = ?8, preserved_snapshot = ?9, restore_key = ?10
             WHERE id = ?11",
            params![
                sandbox.state,
                sandbox.bootstrapped_at.map(timestamp),
                sandbox.last_activity_at.map(timestamp),
                sandbox.stopped_at.map(timestamp),
                sandbox.stopped_reason,
                activity_json,
                timestamp(Utc::now()),
                sandbox.boat_id,
                sandbox.preserved_snapshot,
                sandbox.restore_key,
                sandbox.id,
            ],
        )?;
        Ok(())
    }
}

pub fn status(user: &User, sandbox: Option<Sandbox>, wake_policy: WakePolicy) -> StatusResponse {
    let mut status = StatusResponse {
        username: user.username.clone(),
        sandbox_size: user.size.clone(),
        sandbox_name: None,
        sandbox_id: None,
        ssh_alias: None,
        state: None,
        wake_policy,
        last_activity_at: None,
        stopped_at: None,
        stopped_reason: None,
        activity: None,
        template: user.template.clone(),
        preserved_snapshot: None,
        usage: None,
    };
    if let Some(sandbox) = sandbox {
        status.sandbox_id = sandbox.provisioned().then_some(sandbox.boat_id);
        status.sandbox_name = Some(sandbox.name);
        status.sandbox_size = sandbox.size;
        status.ssh_alias = Some(sandbox.alias);
        status.state = Some(sandbox.state);
        status.last_activity_at = sandbox.last_activity_at;
        status.stopped_at = sandbox.stopped_at;
        status.stopped_reason = sandbox.stopped_reason;
        status.activity = sandbox.last_activity;
        status.template = sandbox.template;
        status.preserved_snapshot = sandbox.preserved_snapshot;
    }
    status
}
