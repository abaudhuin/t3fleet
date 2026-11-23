use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use chrono::{TimeDelta, Utc};
use serde::Deserialize;
use t3fleet_protocol::{
    DEFAULT_SANDBOX_NAME, PairRequest, PairResponse, SandboxActivity, StatusResponse, WakeIntent,
    WakePolicy,
};
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    ApiError, App,
    db::{Sandbox, User},
    provider::{
        CreateSandboxSpec, GuestUser, RemoteSandbox, ResumeOutcome, SandboxState, SnapshotStatus,
    },
};

const WAIT_FOR_T3: &str = r#"timeout 25 sh -c 'until ss -Htl "sport = :3773" 2>/dev/null | grep -q . || curl -sS --max-time 1 -o /dev/null http://127.0.0.1:3773/ 2>/dev/null; do sleep 1; done'"#;

pub(crate) const RETENTION_SNAPSHOT_PREFIX: &str = "t3fleet-keep-";

fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\"'\"'"))
}

fn systemd_word(word: &str) -> String {
    if word
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_/-.:=".contains(&b))
    {
        return word.into();
    }
    format!(
        "\"{}\"",
        word.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}

fn bootstrap_script(guest: &GuestUser) -> Result<String> {
    ensure!(
        !guest.username.is_empty()
            && !guest.username.chars().any(char::is_control)
            && !guest.username.ends_with('\\'),
        "invalid guest username for systemd"
    );
    let user = shell_quote(&guest.username);
    let home = shell_quote(&guest.home_dir);
    let bin = format!("{}/.local/bin", guest.home_dir);
    let profile = shell_quote(&format!("export PATH={}:\"$PATH\"", shell_quote(&bin)));
    let service_user = guest.username.replace('%', "%%");
    let service_home = systemd_word(&format!("HOME={}", guest.home_dir));
    let service_t3_home = systemd_word(&format!("T3CODE_HOME={}/.t3", guest.home_dir));
    let service_path = systemd_word(&format!(
        "PATH={bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ));
    Ok(format!(
        r#"set -eu
guest_user={user}
guest_home={home}
if [ -x "$guest_home/.local/bin/t3" ] && systemctl is-active --quiet t3code; then
    exit 0
fi
if [ ! -x "$guest_home/.local/bin/t3" ]; then
    if [ "$(id -un)" = "$guest_user" ]; then
        env HOME="$guest_home" bash -o pipefail -c 'curl -fsSL https://t3.codes/install.sh | sh'
    else
        sudo -u "$guest_user" -- env HOME="$guest_home" bash -o pipefail -c 'curl -fsSL https://t3.codes/install.sh | sh'
    fi
fi
printf '%s\n' {profile} | sudo tee /etc/profile.d/t3fleet.sh >/dev/null
sudo tee /etc/systemd/system/t3code.service >/dev/null <<'SERVICE'
[Unit]
Description=T3 Code
After=network-online.target
Wants=network-online.target

[Service]
User={service_user}
Environment={service_home}
Environment={service_t3_home}
Environment={service_path}
ExecStart=:/bin/sh -c 'cd "$HOME" && exec "$HOME/.local/bin/t3" serve --host 127.0.0.1 --port 3773'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload
sudo systemctl enable --now t3code
{WAIT_FOR_T3}
"#
    ))
}

const PROBE: &str = r#"set -eu
ssh_conns=$(ss -Htn state established '( sport = :22 )' 2>/dev/null || true)
t3_http_conns=$(ss -Htn state established '( sport = :3773 )' 2>/dev/null || true)
ptys=$(who 2>/dev/null | awk '$2 ~ /^pts\//' || true)
count_lines() {
    if [ -n "$1" ]; then printf '%s\n' "$1" | wc -l; else printf 0; fi
}
python3 - "$1" "$(count_lines "$ssh_conns")" "$(count_lines "$t3_http_conns")" "$(count_lines "$ptys")" <<'PY'
import json, os, sqlite3, sys
from pathlib import Path
userdata = Path(sys.argv[1]) / ".t3" / "userdata"
ssh_conns, t3_http_conns, interactive_ptys = [int(x) for x in sys.argv[2:5]]
provider_procs = 0
pdir = userdata / "provider-processes"
if os.path.isdir(pdir):
    for name in os.listdir(pdir):
        if name.endswith(".json"):
            try:
                with open(os.path.join(pdir, name), "r", encoding="utf-8") as f:
                    data = json.load(f)
                procs = data.get("processes")
                if isinstance(procs, list):
                    provider_procs += len(procs)
            except Exception:
                pass
res = {
    "active_turns": 0,
    "active_sessions": 0,
    "streaming_messages": 0,
    "provider_procs": provider_procs,
    "interactive_ptys": interactive_ptys,
    "ssh_conns": ssh_conns,
    "t3_http_conns": t3_http_conns,
    "latest_t3_activity_at": None,
}
db = userdata / "statev2.sqlite"
if os.path.exists(db):
    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=2.0)
    try:
        cur = conn.cursor()
        tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        has_legacy = "projection_turns" in tables
        has_v2 = "orchestration_v2_projection_provider_turns" in tables
        # Reporting zero work for a schema we cannot read would let the watchdog
        # stop a running agent, so fail the probe and skip this stop decision.
        if tables and not (has_legacy or has_v2):
            sys.exit("unsupported T3 Code database schema")
        def count(q):
            return int(cur.execute(q).fetchone()[0])
        def scalar(q):
            try:
                row = cur.execute(q).fetchone()
                return row[0] if row and row[0] is not None else None
            except sqlite3.Error:
                return None
        ts = []
        if has_legacy:
            res["active_turns"] += count("SELECT COUNT(*) FROM projection_turns WHERE completed_at IS NULL AND state IN ('queued','starting','running')")
            res["active_sessions"] += count("SELECT COUNT(*) FROM projection_thread_sessions WHERE active_turn_id IS NOT NULL OR status IN ('running','starting','working','waiting')")
            res["streaming_messages"] += count("SELECT COUNT(*) FROM projection_thread_messages WHERE is_streaming = 1")
            ts += [
                scalar("SELECT MAX(updated_at) FROM projection_threads WHERE deleted_at IS NULL"),
                scalar("SELECT MAX(latest_user_message_at) FROM projection_threads WHERE deleted_at IS NULL"),
                scalar("SELECT MAX(requested_at) FROM projection_turns"),
            ]
        if has_v2:
            res["active_turns"] += count("SELECT COUNT(*) FROM orchestration_v2_projection_provider_turns WHERE completed_at IS NULL AND status IN ('queued','starting','running')")
            res["active_sessions"] += count("SELECT COUNT(*) FROM orchestration_v2_projection_provider_sessions WHERE status IN ('starting','running','waiting')")
            res["streaming_messages"] += count("SELECT COUNT(*) FROM orchestration_v2_projection_messages WHERE streaming = 1")
            ts += [
                scalar("SELECT MAX(updated_at) FROM orchestration_v2_projection_threads WHERE deleted_at IS NULL"),
                scalar("SELECT MAX(started_at) FROM orchestration_v2_projection_provider_turns"),
            ]
        ts = [t for t in ts if isinstance(t, str) and t]
        if ts:
            res["latest_t3_activity_at"] = max(ts)
    finally:
        conn.close()
print(json.dumps(res))
PY
"#;

fn probe_script(guest: &GuestUser) -> String {
    format!("set -- {}\n{PROBE}", shell_quote(&guest.home_dir))
}

fn pairing_command(guest: &GuestUser, base_url: &str, label: &str) -> String {
    let user = shell_quote(&guest.username);
    let home = shell_quote(&guest.home_dir);
    let base_url = shell_quote(base_url);
    let label = shell_quote(label);
    format!(
        r#"set -eu
guest_user={user}
guest_home={home}
sudo systemctl start t3code
{WAIT_FOR_T3}
set -- env HOME="$guest_home" "$guest_home/.local/bin/t3" auth pairing create \
    --base-dir "$guest_home/.t3" --base-url {base_url} --label {label} --ttl '15m' --json
if [ "$(id -un)" = "$guest_user" ]; then
    "$@"
else
    sudo -u "$guest_user" -- "$@"
fi
"#
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pairing {
    credential: String,
    pair_url: String,
    expires_at: chrono::DateTime<Utc>,
}

fn retention_snapshot_name(provider_sandbox_id: &str) -> String {
    format!(
        "{RETENTION_SNAPSHOT_PREFIX}{}",
        provider_sandbox_id.replace('_', "-")
    )
}

fn elapsed(time: chrono::DateTime<Utc>) -> Duration {
    (Utc::now() - time).to_std().unwrap_or_default()
}

impl App {
    async fn sync(&self, sandbox: &mut Sandbox) -> Result<Option<RemoteSandbox>> {
        let provider = self.provider(sandbox)?;
        let Some(remote) = provider.get(&sandbox.provider_sandbox_id).await? else {
            ensure!(sandbox.state.is_stopped(), "provider sandbox not found");
            return Ok(None);
        };
        if remote.state.is_stopped() {
            self.record_stop(sandbox, None, &remote)?;
        } else if sandbox.state != remote.state {
            sandbox.state = remote.state;
            self.db.save_sandbox(sandbox)?;
        }
        Ok(Some(remote))
    }

    fn record_stop(
        &self,
        sandbox: &mut Sandbox,
        reason: Option<&str>,
        remote: &RemoteSandbox,
    ) -> Result<()> {
        sandbox.state = remote.state;
        sandbox.stopped_at = Some(
            remote
                .stopped_at
                .or(sandbox.stopped_at)
                .unwrap_or_else(Utc::now),
        );
        if let Some(reason) = reason {
            sandbox.stopped_reason = Some(reason.into());
        } else if sandbox.stopped_reason.is_none() {
            sandbox.stopped_reason = Some("idle".into());
        }
        self.db.save_sandbox(sandbox)?;
        Ok(())
    }

    pub(crate) fn record_activity(&self, sandbox: &mut Sandbox) -> Result<()> {
        sandbox.state = SandboxState::Running;
        sandbox.last_activity_at = Some(Utc::now());
        sandbox.stopped_at = None;
        sandbox.stopped_reason = None;
        self.db.save_sandbox(sandbox)?;
        Ok(())
    }

    pub(crate) async fn sandbox_status(
        &self,
        user: &User,
        mut sandbox: Option<Sandbox>,
        include_usage: bool,
    ) -> Result<StatusResponse> {
        let mut usage = None;
        if let Some(sandbox) = sandbox.as_mut().filter(|sandbox| sandbox.provisioned()) {
            self.sync(sandbox).await?;
            if include_usage {
                usage = self.sandbox_usage(sandbox).await?;
            }
        }
        let mut status = self.status(user, sandbox)?;
        status.usage = usage;
        Ok(status)
    }

    pub(crate) async fn ready(
        &self,
        user: &User,
        name: &str,
        intent: WakeIntent,
    ) -> Result<Sandbox, ApiError> {
        let sandbox = match self.db.sandbox(user, name)? {
            Some(sandbox) => sandbox,
            None if name == DEFAULT_SANDBOX_NAME => {
                let provider = self.default_provider()?;
                let template = user
                    .template
                    .as_deref()
                    .or(self.default_template.as_deref());
                self.validate_provider_template(provider, template)?;
                self.db
                    .reserve_sandbox(user, name, &user.size, template, provider.name())?
                    .ok_or_else(|| ApiError::conflict("SSH alias is already in use"))?
            }
            None => return Err(ApiError::sandbox_not_found()),
        };
        self.start_sandbox(user, sandbox, intent).await
    }

    pub(crate) async fn start_sandbox(
        &self,
        user: &User,
        mut sandbox: Sandbox,
        intent: WakeIntent,
    ) -> Result<Sandbox, ApiError> {
        let provider = self.provider(&sandbox)?;
        let lease_ttl_secs = provider.capabilities().lease_ttl.then_some(self.safety_ttl);
        let mut remote = if sandbox.provisioned() {
            self.sync(&mut sandbox).await?
        } else {
            self.validate_provider_template(provider, sandbox.template.as_deref())?;
            let remote = provider
                .create(CreateSandboxSpec {
                    owner: &user.username,
                    sandbox_name: &sandbox.name,
                    size: &sandbox.size,
                    template: sandbox.template.as_deref(),
                    lease_ttl_secs,
                    idempotency_key: &sandbox.id,
                })
                .await?;
            sandbox.provider_sandbox_id.clone_from(&remote.id);
            sandbox.state = remote.state;
            self.db.save_sandbox(&sandbox)?;
            Some(remote)
        };
        if remote
            .as_ref()
            .is_some_and(|remote| remote.state.is_stopping())
        {
            let stopped = provider
                .wait_for(&sandbox.provider_sandbox_id, true)
                .await?;
            self.record_stop(&mut sandbox, None, &stopped)?;
            remote = Some(stopped);
        }
        if remote
            .as_ref()
            .is_none_or(|remote| remote.state.is_stopped())
        {
            if matches!(intent, WakeIntent::SshProxy) {
                match self.wake_policy {
                    WakePolicy::Explicit => {
                        return Err(ApiError::conflict(
                            "Sandbox is stopped and wake policy is 'explicit'. Run 't3fleet wake' to start it.",
                        ));
                    }
                    WakePolicy::AggressiveIdle => {
                        let reason = sandbox.stopped_reason.as_deref().unwrap_or("stopped");
                        return Err(ApiError::conflict(&format!(
                            "Sandbox is stopped ({reason}) under aggressive-idle policy to avoid auto-reconnect wake loops. Run 't3fleet wake' to start it."
                        )));
                    }
                    WakePolicy::Auto => match sandbox.stopped_reason.as_deref() {
                        Some("manual") => {
                            return Err(ApiError::conflict(
                                "Sandbox is manually stopped. Run 't3fleet wake' to start it.",
                            ));
                        }
                        Some("idle")
                            if sandbox
                                .stopped_at
                                .is_some_and(|at| elapsed(at) < self.cooldown) =>
                        {
                            return Err(ApiError::conflict(
                                "Sandbox recently auto-stopped; cooling down to prevent wake/sleep loops. Run 't3fleet wake' or retry shortly.",
                            ));
                        }
                        _ => {}
                    },
                }
            }
            match provider
                .resume(&sandbox.provider_sandbox_id, lease_ttl_secs)
                .await?
            {
                ResumeOutcome::Ready(remote) => {
                    if !remote.state.is_running() {
                        provider
                            .wait_for(&sandbox.provider_sandbox_id, false)
                            .await?;
                    }
                }
                ResumeOutcome::Expired => self.restore(user, &mut sandbox).await?,
            }
        } else if remote.is_some_and(|remote| !remote.state.is_running()) {
            provider
                .wait_for(&sandbox.provider_sandbox_id, false)
                .await?;
        }

        self.cleanup_snapshot(&mut sandbox).await?;

        if sandbox.bootstrapped_at.is_none() && !self.skip_bootstrap {
            let command = bootstrap_script(&provider.guest_user())?;
            provider
                .exec(
                    &sandbox.provider_sandbox_id,
                    &command,
                    Duration::from_secs(300),
                )
                .await?;
            sandbox.bootstrapped_at = Some(Utc::now());
        }
        self.record_activity(&mut sandbox)?;
        Ok(sandbox)
    }

    async fn restore(&self, user: &User, sandbox: &mut Sandbox) -> Result<()> {
        let provider = self.provider(sandbox)?;
        let snapshot = sandbox
            .preserved_snapshot
            .as_deref()
            .filter(|name| {
                provider.capabilities().snapshot_retention
                    && *name == retention_snapshot_name(&sandbox.provider_sandbox_id)
            })
            .context("stopped sandbox expired without a saved snapshot")?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let saved = provider
                    .saved_snapshot(snapshot)
                    .await?
                    .context("preserved snapshot is missing")?;
                ensure!(
                    saved.belongs_to(&sandbox.provider_sandbox_id),
                    "saved snapshot belongs to a different sandbox"
                );
                ensure!(
                    saved
                        .created_at
                        .zip(sandbox.stopped_at)
                        .is_none_or(|(created, stopped)| created >= stopped),
                    "saved snapshot predates the sandbox's last stop"
                );
                match saved.status {
                    SnapshotStatus::Ready => return Ok(()),
                    SnapshotStatus::Failed => bail!(
                        "could not preserve sandbox snapshot: {}",
                        saved.error.as_deref().unwrap_or("unknown error"),
                    ),
                    SnapshotStatus::Saving => sleep(Duration::from_secs(1)).await,
                }
            }
        })
        .await
        .context("snapshot is still saving; retry wake shortly")??;
        let key = match &sandbox.restore_key {
            Some(key) => key.clone(),
            None => {
                let key = Uuid::new_v4().to_string();
                sandbox.restore_key = Some(key.clone());
                self.db.save_sandbox(sandbox)?;
                key
            }
        };
        let restored = provider
            .create(CreateSandboxSpec {
                owner: &user.username,
                sandbox_name: &sandbox.name,
                size: &sandbox.size,
                template: Some(snapshot),
                lease_ttl_secs: provider.capabilities().lease_ttl.then_some(self.safety_ttl),
                idempotency_key: &key,
            })
            .await?;
        let remote = if restored.state.is_running() {
            restored
        } else {
            provider.wait_for(&restored.id, false).await?
        };
        let old_id = std::mem::replace(&mut sandbox.provider_sandbox_id, remote.id);
        sandbox.state = remote.state;
        sandbox.restore_key = None;
        sandbox.last_activity = None;
        self.db.save_sandbox(sandbox)?;
        if old_id != sandbox.provider_sandbox_id
            && let Err(error) = provider.delete(&old_id).await
        {
            tracing::warn!(sandbox_id = %old_id, %error, "could not delete expired sandbox");
        }
        Ok(())
    }

    async fn cleanup_snapshot(&self, sandbox: &mut Sandbox) -> Result<()> {
        let provider = self.provider(sandbox)?;
        if provider.capabilities().snapshot_retention
            && let Some(snapshot) = &sandbox.preserved_snapshot
        {
            match provider.delete_saved_snapshot(snapshot).await {
                Ok(()) => {
                    sandbox.preserved_snapshot = None;
                    sandbox.restore_key = None;
                    self.db.save_sandbox(sandbox)?;
                }
                Err(error) => {
                    tracing::warn!(%snapshot, %error, "could not clean up saved snapshot")
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn prepare_enrollment(&self, user: &User) -> Result<Sandbox, ApiError> {
        if let Some(mut sandbox) = self.db.sandbox(user, DEFAULT_SANDBOX_NAME)?
            && sandbox.provisioned()
            && (self.skip_bootstrap || sandbox.bootstrapped_at.is_some())
            && self
                .sync(&mut sandbox)
                .await?
                .is_none_or(|remote| remote.state.is_stopped())
        {
            return Ok(sandbox);
        }
        self.ready(user, DEFAULT_SANDBOX_NAME, WakeIntent::Explicit)
            .await
    }

    pub(crate) async fn stop(&self, sandbox: &mut Sandbox, reason: &str) -> Result<()> {
        if !sandbox.provisioned() {
            return Ok(());
        }
        let Some(remote) = self.sync(sandbox).await? else {
            return Ok(());
        };
        if remote.state.is_stopped() {
            return self.record_stop(sandbox, Some(reason), &remote);
        }
        let provider = self.provider(sandbox)?;
        if !remote.state.is_stopping() {
            provider.suspend(&sandbox.provider_sandbox_id).await?;
        }
        sandbox.stopped_reason = Some(reason.into());
        self.db.save_sandbox(sandbox)?;
        let remote = provider
            .wait_for(&sandbox.provider_sandbox_id, true)
            .await?;
        self.record_stop(sandbox, Some(reason), &remote)
    }

    pub(crate) async fn delete_sandbox(&self, user: &User, sandbox: Sandbox) -> Result<()> {
        let provider = self.provider(&sandbox)?;
        if provider.capabilities().snapshot_retention
            && let Some(snapshot) = &sandbox.preserved_snapshot
        {
            provider.delete_saved_snapshot(snapshot).await?;
        }
        if sandbox.provisioned() {
            provider.delete(&sandbox.provider_sandbox_id).await?;
        }
        self.db.delete_sandbox(user, &sandbox.name)?;
        Ok(())
    }

    pub(crate) async fn pairing(
        &self,
        sandbox: &Sandbox,
        request: PairRequest,
    ) -> Result<PairResponse> {
        let base_url = format!("http://127.0.0.1:{}", request.local_port);
        let provider = self.provider(sandbox)?;
        let command = pairing_command(&provider.guest_user(), &base_url, &request.label);
        let stdout = provider
            .exec(
                &sandbox.provider_sandbox_id,
                &command,
                Duration::from_secs(300),
            )
            .await?;
        let pairing: Pairing = serde_json::from_str(&stdout).context("invalid T3 pairing JSON")?;
        ensure!(
            !pairing.credential.is_empty() && !pairing.pair_url.is_empty(),
            "incomplete T3 pairing response"
        );

        let mut link = reqwest::Url::parse("t3code://pair")?;
        link.query_pairs_mut()
            .append_pair("pairingUrl", &pairing.pair_url);
        Ok(PairResponse {
            pair_url: pairing.pair_url,
            t3_deep_link: link.into(),
            credential: pairing.credential,
            expires_at: pairing.expires_at,
            local_port: request.local_port,
            ssh_alias: sandbox.alias.clone(),
        })
    }

    pub(crate) async fn watch_sandbox(&self, mut sandbox: Sandbox) -> Result<()> {
        let remote = self.sync(&mut sandbox).await?;
        if sandbox.state.is_stopped() {
            return self.preserve_snapshot(&mut sandbox).await;
        }
        let Some(remote) = remote.filter(|remote| remote.state.is_running()) else {
            return Ok(());
        };
        self.cleanup_snapshot(&mut sandbox).await?;

        let provider = self.provider(&sandbox)?;
        let command = probe_script(&provider.guest_user());
        let output = provider
            .exec(
                &sandbox.provider_sandbox_id,
                &command,
                Duration::from_secs(15),
            )
            .await?;
        let activity: SandboxActivity =
            serde_json::from_str(&output).context("invalid activity probe output")?;
        if let Some(t3_ts) = activity.latest_t3_activity_at
            && sandbox.last_activity_at.is_none_or(|prev| t3_ts > prev)
        {
            sandbox.last_activity_at = Some(t3_ts);
        }
        sandbox.last_activity = Some(activity.clone());

        let actively_working = match self.wake_policy {
            WakePolicy::Auto => activity.has_active_work() || activity.has_connections(),
            WakePolicy::AggressiveIdle | WakePolicy::Explicit => activity.has_active_work(),
        };

        if actively_working {
            self.record_activity(&mut sandbox)?;
            if provider.capabilities().lease_ttl
                && remote
                    .lease_expires_at
                    .is_none_or(|at| at - Utc::now() <= TimeDelta::minutes(30))
            {
                provider
                    .extend_lease(&sandbox.provider_sandbox_id, self.safety_ttl)
                    .await?;
            }
        } else if sandbox
            .last_activity_at
            .is_some_and(|at| elapsed(at) >= self.idle_timeout)
        {
            self.stop(&mut sandbox, "idle").await?;
        } else {
            self.db.save_sandbox(&sandbox)?;
        }
        Ok(())
    }

    async fn preserve_snapshot(&self, sandbox: &mut Sandbox) -> Result<()> {
        let provider = self.provider(sandbox)?;
        let retention = self.snapshot_retention_days.saturating_mul(86_400);
        if !provider.capabilities().snapshot_retention
            || retention == 0
            || sandbox
                .stopped_at
                .is_none_or(|at| elapsed(at).as_secs() < retention)
        {
            return Ok(());
        }
        let name = retention_snapshot_name(&sandbox.provider_sandbox_id);
        if let Some(existing) = &sandbox.preserved_snapshot
            && let Some(snapshot) = provider.saved_snapshot(existing).await?
        {
            let current = *existing == name
                && snapshot.belongs_to(&sandbox.provider_sandbox_id)
                && snapshot
                    .created_at
                    .zip(sandbox.stopped_at)
                    .is_none_or(|(created, stopped)| created >= stopped);
            if current && !matches!(snapshot.status, SnapshotStatus::Failed) {
                return Ok(());
            }
            provider.delete_saved_snapshot(existing).await?;
        }
        provider
            .save_snapshot(&sandbox.provider_sandbox_id, &name)
            .await?;
        sandbox.preserved_snapshot = Some(name);
        self.db.save_sandbox(sandbox)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod probe_tests {
    use super::*;
    use rusqlite::Connection;
    use std::process::{Command, Output};
    use tempfile::TempDir;

    const V2_SCHEMA: &str = "
        CREATE TABLE orchestration_v2_projection_provider_turns (
            provider_turn_id TEXT PRIMARY KEY, status TEXT NOT NULL,
            started_at TEXT, completed_at TEXT);
        CREATE TABLE orchestration_v2_projection_provider_sessions (
            provider_session_id TEXT PRIMARY KEY, status TEXT NOT NULL);
        CREATE TABLE orchestration_v2_projection_messages (
            message_id TEXT PRIMARY KEY, streaming INTEGER NOT NULL);
        CREATE TABLE orchestration_v2_projection_threads (
            thread_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, deleted_at TEXT);
    ";

    fn home_with_db(sql: &str) -> TempDir {
        let home = TempDir::new().unwrap();
        let userdata = home.path().join(".t3/userdata");
        std::fs::create_dir_all(&userdata).unwrap();
        Connection::open(userdata.join("statev2.sqlite"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        home
    }

    fn run_probe(home: &TempDir) -> Output {
        let guest = GuestUser {
            username: "user".into(),
            home_dir: home.path().to_str().unwrap().into(),
        };
        Command::new("sh")
            .args(["-c", &probe_script(&guest)])
            .output()
            .unwrap()
    }

    fn activity(home: &TempDir) -> SandboxActivity {
        let output = run_probe(home);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    #[test]
    fn probe_reports_running_work_from_v2_tables() {
        let home = home_with_db(&format!(
            "{V2_SCHEMA}
            INSERT INTO orchestration_v2_projection_provider_turns
                VALUES ('t1', 'running', '2026-11-23T19:00:00.000Z', NULL);
            INSERT INTO orchestration_v2_projection_provider_sessions VALUES ('s1', 'running');
            INSERT INTO orchestration_v2_projection_messages VALUES ('m1', 1);
            INSERT INTO orchestration_v2_projection_threads
                VALUES ('th1', '2026-11-23T19:00:05.000Z', NULL);"
        ));
        let activity = activity(&home);
        assert_eq!(activity.active_turns, 1);
        assert_eq!(activity.active_sessions, 1);
        assert_eq!(activity.streaming_messages, 1);
        assert_eq!(
            activity.latest_t3_activity_at.unwrap().to_rfc3339(),
            "2026-11-23T19:00:05+00:00"
        );
    }

    #[test]
    fn probe_ignores_finished_v2_work() {
        let home = home_with_db(&format!(
            "{V2_SCHEMA}
            INSERT INTO orchestration_v2_projection_provider_turns
                VALUES ('t1', 'completed', '2026-11-23T19:00:00.000Z', '2026-11-23T19:00:09.000Z');
            INSERT INTO orchestration_v2_projection_provider_sessions VALUES ('s1', 'ready');
            INSERT INTO orchestration_v2_projection_messages VALUES ('m1', 0);"
        ));
        // Not `has_active_work`, which also counts the test host's login shells.
        let activity = activity(&home);
        assert_eq!(activity.active_turns, 0);
        assert_eq!(activity.active_sessions, 0);
        assert_eq!(activity.streaming_messages, 0);
    }

    #[test]
    fn probe_fails_on_unknown_schema_instead_of_reporting_idle() {
        let home = home_with_db("CREATE TABLE some_future_table (id TEXT);");
        let output = run_probe(&home);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported"));
    }
}
