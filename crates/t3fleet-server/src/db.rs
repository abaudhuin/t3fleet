use std::{path::Path, sync::Mutex};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params};
use t3fleet_protocol::{SandboxActivity, StatusResponse, WakePolicy};
use uuid::Uuid;

pub const DEFAULT_SANDBOX_NAME: &str = "default";

pub struct Db(Mutex<Connection>);

pub struct User {
    pub id: String,
    pub username: String,
    pub size: String,
}

pub struct Sandbox {
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
    })
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
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

    pub fn create_user(&self, username: String, size: String) -> rusqlite::Result<User> {
        let user = User {
            id: Uuid::new_v4().to_string(),
            username,
            size,
        };
        self.0.lock().unwrap().execute(
            "INSERT INTO users(id, username, sandbox_size, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user.id, user.username, user.size, timestamp(Utc::now())],
        )?;
        Ok(user)
    }

    pub fn user(&self, username: &str) -> rusqlite::Result<Option<User>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, username, sandbox_size FROM users WHERE username = ?1",
                [username],
                user_row,
            )
            .optional()
    }

    pub fn users(&self, watched: bool) -> rusqlite::Result<Vec<User>> {
        let conn = self.0.lock().unwrap();
        let mut statement = conn.prepare(if watched {
            "SELECT u.id, u.username, u.sandbox_size FROM users u
             JOIN sandboxes s ON s.user_id = u.id
             WHERE s.state IN ('running', 'ready', 'idle') ORDER BY u.username"
        } else {
            "SELECT id, username, sandbox_size FROM users ORDER BY username"
        })?;
        statement.query_map([], user_row)?.collect()
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
                "SELECT u.id, u.username, u.sandbox_size FROM users u
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
                "SELECT u.id, u.username, u.sandbox_size FROM users u
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

    pub fn sandbox(&self, user: &User) -> rusqlite::Result<Option<Sandbox>> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT name, boat_sandbox_id, ssh_alias, state, bootstrapped_at, last_activity_at,
                    stopped_at, stopped_reason, last_activity_json
                 FROM sandboxes WHERE user_id = ?1 AND name = ?2",
                params![&user.id, DEFAULT_SANDBOX_NAME],
                |row| {
                    let activity_json: Option<String> = row.get(8)?;
                    let last_activity = activity_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str(raw).ok());
                    Ok(Sandbox {
                        name: row.get(0)?,
                        boat_id: row.get(1)?,
                        alias: row.get(2)?,
                        state: row.get(3)?,
                        bootstrapped_at: time_column(row, 4)?,
                        last_activity_at: time_column(row, 5)?,
                        stopped_at: time_column(row, 6)?,
                        stopped_reason: row.get(7)?,
                        last_activity,
                    })
                },
            )
            .optional()
    }

    pub fn add_sandbox(&self, user: &User, boat_id: &str, state: &str) -> rusqlite::Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO sandboxes(id, user_id, name, boat_sandbox_id, ssh_alias, size, state,
                                   last_activity_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?8)",
            params![
                Uuid::new_v4().to_string(),
                user.id,
                DEFAULT_SANDBOX_NAME,
                boat_id,
                format!("t3fleet-{}", user.username),
                user.size,
                state,
                timestamp(Utc::now())
            ],
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
                    stopped_at = ?4, stopped_reason = ?5, last_activity_json = ?6, updated_at = ?7
             WHERE boat_sandbox_id = ?8",
            params![
                sandbox.state,
                sandbox.bootstrapped_at.map(timestamp),
                sandbox.last_activity_at.map(timestamp),
                sandbox.stopped_at.map(timestamp),
                sandbox.stopped_reason,
                activity_json,
                timestamp(Utc::now()),
                sandbox.boat_id
            ],
        )?;
        Ok(())
    }

    pub fn status(&self, user: User, wake_policy: WakePolicy) -> rusqlite::Result<StatusResponse> {
        let sandbox = self.sandbox(&user)?;
        let mut status = StatusResponse {
            username: user.username,
            sandbox_size: user.size,
            sandbox_name: None,
            sandbox_id: None,
            ssh_alias: None,
            state: None,
            wake_policy,
            last_activity_at: None,
            stopped_at: None,
            stopped_reason: None,
            activity: None,
        };
        if let Some(sandbox) = sandbox {
            status.sandbox_name = Some(sandbox.name);
            status.sandbox_id = Some(sandbox.boat_id);
            status.ssh_alias = Some(sandbox.alias);
            status.state = Some(sandbox.state);
            status.last_activity_at = sandbox.last_activity_at;
            status.stopped_at = sandbox.stopped_at;
            status.stopped_reason = sandbox.stopped_reason;
            status.activity = sandbox.last_activity;
        }
        Ok(status)
    }
}
