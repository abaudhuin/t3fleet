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
    boat::{RemoteSandbox, ResumeOutcome, SnapshotStatus},
    db::{self, Sandbox, User},
};

const WAIT_FOR_T3: &str = r#"timeout 25 sh -c 'until ss -Htl "sport = :3773" 2>/dev/null | grep -q . || curl -sS --max-time 1 -o /dev/null http://127.0.0.1:3773/ 2>/dev/null; do sleep 1; done'"#;

pub(crate) const RETENTION_SNAPSHOT_PREFIX: &str = "t3fleet-keep-";

const BOOTSTRAP: &str = r#"set -eu
if [ -x /home/user/.local/bin/t3 ] && systemctl is-active --quiet t3code; then
    exit 0
fi
if [ ! -x /home/user/.local/bin/t3 ]; then
    if [ "$(id -un)" = "user" ]; then
        env HOME=/home/user bash -o pipefail -c 'curl -fsSL https://t3.codes/install.sh | sh'
    else
        sudo -u user env HOME=/home/user bash -o pipefail -c 'curl -fsSL https://t3.codes/install.sh | sh'
    fi
fi
sudo tee /etc/profile.d/t3fleet.sh >/dev/null <<'PROFILE'
export PATH="/home/user/.local/bin:$PATH"
PROFILE
sudo tee /etc/systemd/system/t3code.service >/dev/null <<'SERVICE'
[Unit]
Description=T3 Code
After=network-online.target
Wants=network-online.target

[Service]
User=user
Environment=HOME=/home/user
Environment=T3CODE_HOME=/home/user/.t3
Environment=PATH=/home/user/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=/home/user
ExecStart=/home/user/.local/bin/t3 serve --host 127.0.0.1 --port 3773
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload
sudo systemctl enable --now t3code
"#;

const PROBE: &str = r#"set -eu
ssh_conns=$(ss -Htn state established '( sport = :22 )' 2>/dev/null || true)
t3_http_conns=$(ss -Htn state established '( sport = :3773 )' 2>/dev/null || true)
ptys=$(who 2>/dev/null | awk '$2 ~ /^pts\//' || true)
count_lines() {
    if [ -n "$1" ]; then printf '%s\n' "$1" | wc -l; else printf 0; fi
}
python3 - "$(count_lines "$ssh_conns")" "$(count_lines "$t3_http_conns")" "$(count_lines "$ptys")" <<'PY'
import json, os, sqlite3, sys
ssh_conns, t3_http_conns, interactive_ptys = [int(x) for x in sys.argv[1:4]]
provider_procs = 0
pdir = "/home/user/.t3/userdata/provider-processes"
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
db = "/home/user/.t3/userdata/statev2.sqlite"
if os.path.exists(db):
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2.0)
    try:
        cur = conn.cursor()
        def scalar(q):
            try:
                row = cur.execute(q).fetchone()
                return row[0] if row and row[0] is not None else None
            except sqlite3.Error:
                return None
        res["active_turns"] = int(scalar("SELECT COUNT(*) FROM projection_turns WHERE completed_at IS NULL AND state IN ('queued','starting','running')") or 0)
        res["active_sessions"] = int(scalar("SELECT COUNT(*) FROM projection_thread_sessions WHERE active_turn_id IS NOT NULL OR status IN ('running','starting','working','waiting')") or 0)
        res["streaming_messages"] = int(scalar("SELECT COUNT(*) FROM projection_thread_messages WHERE is_streaming = 1") or 0)
        ts = [
            scalar("SELECT MAX(updated_at) FROM projection_threads WHERE deleted_at IS NULL"),
            scalar("SELECT MAX(latest_user_message_at) FROM projection_threads WHERE deleted_at IS NULL"),
            scalar("SELECT MAX(requested_at) FROM projection_turns"),
        ]
        ts = [t for t in ts if isinstance(t, str) and t]
        if ts:
            res["latest_t3_activity_at"] = max(ts)
    finally:
        conn.close()
print(json.dumps(res))
PY
"#;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pairing {
    credential: String,
    pair_url: String,
    expires_at: chrono::DateTime<Utc>,
}

fn retention_snapshot_name(boat_id: &str) -> String {
    format!("{RETENTION_SNAPSHOT_PREFIX}{}", boat_id.replace('_', "-"))
}

fn elapsed(time: chrono::DateTime<Utc>) -> Duration {
    (Utc::now() - time).to_std().unwrap_or_default()
}

impl App {
    async fn sync(&self, sandbox: &mut Sandbox) -> Result<Option<RemoteSandbox>> {
        let Some(remote) = self.boat.get(&sandbox.boat_id).await? else {
            ensure!(sandbox.state == "archived", "Boat sandbox not found");
            return Ok(None);
        };
        if remote.state == "archived" {
            self.record_stop(sandbox, None, &remote)?;
        } else if sandbox.state != remote.state {
            sandbox.state.clone_from(&remote.state);
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
        sandbox.state.clone_from(&remote.state);
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
        sandbox.state = "running".into();
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
                usage = self.boat.usage(&sandbox.boat_id).await?;
            }
        }
        let mut status = db::status(user, sandbox, self.wake_policy);
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
            None if name == DEFAULT_SANDBOX_NAME => self
                .db
                .reserve_sandbox(
                    user,
                    name,
                    &user.size,
                    user.template
                        .as_deref()
                        .or(self.default_template.as_deref()),
                )?
                .ok_or_else(|| ApiError::conflict("SSH alias is already in use"))?,
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
        let mut remote = if sandbox.provisioned() {
            self.sync(&mut sandbox).await?
        } else {
            let remote = self
                .boat
                .create(
                    &user.username,
                    &sandbox,
                    self.safety_ttl,
                    sandbox.template.as_deref(),
                    &sandbox.id,
                )
                .await?;
            sandbox.boat_id.clone_from(&remote.id);
            sandbox.state.clone_from(&remote.state);
            self.db.save_sandbox(&sandbox)?;
            Some(remote)
        };
        if remote.as_ref().is_some_and(RemoteSandbox::stopping) && sandbox.stopped_reason.is_some()
        {
            let archived = self.boat.wait_for(&sandbox.boat_id, true).await?;
            self.record_stop(&mut sandbox, None, &archived)?;
            remote = Some(archived);
        }
        if remote
            .as_ref()
            .is_none_or(|remote| remote.state == "archived")
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
            match self.boat.resume(&sandbox.boat_id, self.safety_ttl).await? {
                ResumeOutcome::Ready(remote) => sandbox.state = remote.state,
                ResumeOutcome::Expired => self.restore(user, &mut sandbox).await?,
            }
        } else if remote.is_some_and(|remote| !remote.running()) {
            self.boat.wait_for(&sandbox.boat_id, false).await?;
        }

        self.cleanup_snapshot(&mut sandbox).await?;

        if sandbox.bootstrapped_at.is_none() && !self.skip_bootstrap {
            let command = format!("{BOOTSTRAP}{WAIT_FOR_T3}");
            self.boat.command(&sandbox.boat_id, &command, 300).await?;
            sandbox.bootstrapped_at = Some(Utc::now());
        }
        self.record_activity(&mut sandbox)?;
        Ok(sandbox)
    }

    async fn restore(&self, user: &User, sandbox: &mut Sandbox) -> Result<()> {
        let snapshot = sandbox
            .preserved_snapshot
            .as_deref()
            .filter(|name| *name == retention_snapshot_name(&sandbox.boat_id))
            .context("Boat's archived sandbox expired without a saved snapshot")?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let saved = self
                    .boat
                    .saved_snapshot(snapshot)
                    .await?
                    .context("preserved Boat snapshot is missing")?;
                ensure!(
                    saved.belongs_to(&sandbox.boat_id),
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
                        "Boat could not preserve sandbox snapshot: {}",
                        saved.error.as_deref().unwrap_or("unknown error"),
                    ),
                    SnapshotStatus::Saving => sleep(Duration::from_secs(1)).await,
                }
            }
        })
        .await
        .context("Boat snapshot is still saving; retry wake shortly")??;
        let key = match &sandbox.restore_key {
            Some(key) => key.clone(),
            None => {
                let key = Uuid::new_v4().to_string();
                sandbox.restore_key = Some(key.clone());
                self.db.save_sandbox(sandbox)?;
                key
            }
        };
        let restored = self
            .boat
            .create(
                &user.username,
                sandbox,
                self.safety_ttl,
                Some(snapshot),
                &key,
            )
            .await?;
        let remote = if restored.running() {
            restored
        } else {
            self.boat.wait_for(&restored.id, false).await?
        };
        let old_id = std::mem::replace(&mut sandbox.boat_id, remote.id);
        sandbox.state = remote.state;
        sandbox.restore_key = None;
        sandbox.last_activity = None;
        self.db.save_sandbox(sandbox)?;
        if old_id != sandbox.boat_id
            && let Err(error) = self.boat.delete(&old_id).await
        {
            tracing::warn!(sandbox_id = %old_id, %error, "could not delete expired sandbox");
        }
        Ok(())
    }

    async fn cleanup_snapshot(&self, sandbox: &mut Sandbox) -> Result<()> {
        if let Some(snapshot) = &sandbox.preserved_snapshot {
            match self.boat.delete_saved_snapshot(snapshot).await {
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
                .is_none_or(|remote| remote.state == "archived")
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
        if remote.state == "archived" {
            return self.record_stop(sandbox, Some(reason), &remote);
        }
        if !remote.stopping() {
            self.boat.request_stop(&sandbox.boat_id).await?;
        }
        sandbox.stopped_reason = Some(reason.into());
        self.db.save_sandbox(sandbox)?;
        let remote = self.boat.wait_for(&sandbox.boat_id, true).await?;
        self.record_stop(sandbox, Some(reason), &remote)
    }

    pub(crate) async fn delete_sandbox(&self, user: &User, sandbox: Sandbox) -> Result<()> {
        if let Some(snapshot) = &sandbox.preserved_snapshot {
            self.boat.delete_saved_snapshot(snapshot).await?;
        }
        if sandbox.provisioned() {
            self.boat.delete(&sandbox.boat_id).await?;
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
        let label = request.label.replace('\'', "'\"'\"'");
        let command = format!(
            "set -eu\nsudo systemctl start t3code\n{WAIT_FOR_T3}\n\
             if [ \"$(id -un)\" = \"user\" ]; then\n\
               env HOME=/home/user /home/user/.local/bin/t3 auth pairing create \
                 --base-dir /home/user/.t3 --base-url '{base_url}' --label '{label}' --ttl '15m' --json\n\
             else\n\
               sudo -u user env HOME=/home/user /home/user/.local/bin/t3 auth pairing create \
                 --base-dir /home/user/.t3 --base-url '{base_url}' --label '{label}' --ttl '15m' --json\n\
             fi"
        );
        let stdout = self.boat.command(&sandbox.boat_id, &command, 300).await?;
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
        if sandbox.state == "archived" {
            return self.preserve_snapshot(&mut sandbox).await;
        }
        let Some(remote) = remote.filter(RemoteSandbox::running) else {
            return Ok(());
        };
        self.cleanup_snapshot(&mut sandbox).await?;

        let output = self.boat.command(&sandbox.boat_id, PROBE, 15).await?;
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
            if remote
                .archive_after
                .is_none_or(|at| at - Utc::now() <= TimeDelta::minutes(30))
            {
                self.boat.ttl(&sandbox.boat_id, self.safety_ttl).await?;
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
        let retention = self.snapshot_retention_days.saturating_mul(86_400);
        if retention == 0
            || sandbox
                .stopped_at
                .is_none_or(|at| elapsed(at).as_secs() < retention)
        {
            return Ok(());
        }
        let name = retention_snapshot_name(&sandbox.boat_id);
        if let Some(existing) = &sandbox.preserved_snapshot
            && let Some(snapshot) = self.boat.saved_snapshot(existing).await?
        {
            let current = *existing == name
                && snapshot.belongs_to(&sandbox.boat_id)
                && snapshot
                    .created_at
                    .zip(sandbox.stopped_at)
                    .is_none_or(|(created, stopped)| created >= stopped);
            if current && !matches!(snapshot.status, SnapshotStatus::Failed) {
                return Ok(());
            }
            self.boat.delete_saved_snapshot(existing).await?;
        }
        self.boat.save_snapshot(&sandbox.boat_id, &name).await?;
        sandbox.preserved_snapshot = Some(name);
        self.db.save_sandbox(sandbox)?;
        Ok(())
    }
}
