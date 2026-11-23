use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode, Url, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use t3fleet_protocol::SandboxUsage;
use tokio::time::{Instant, sleep};

use crate::{
    provider::{
        CreateSandboxSpec, GuestUser, ProviderCapabilities, RemoteSandbox, ResumeOutcome,
        SandboxProvider, SandboxState, SavedSnapshot, SnapshotStatus, SshAccess,
    },
    sandbox_alias,
};

const TRANSIENT_SSH_ERRORS: &[&str] = &[
    "sandbox_restoring",
    "sandbox_securing",
    "sandbox_starting",
    "machine_not_running",
];

pub struct BoatProvider {
    http: Client,
    base: Url,
}

#[derive(Deserialize)]
struct BoatSandbox {
    id: String,
    state: String,
    error: Option<String>,
    #[serde(rename = "archiveAfter")]
    archive_after: Option<DateTime<Utc>>,
    #[serde(rename = "stoppedAt")]
    stopped_at: Option<DateTime<Utc>>,
}

impl From<BoatSandbox> for RemoteSandbox {
    fn from(sandbox: BoatSandbox) -> Self {
        Self {
            id: sandbox.id,
            state: match sandbox.state.as_str() {
                "ready" | "idle" | "running" => SandboxState::Running,
                "archiving" | "stopping" => SandboxState::Stopping,
                "archived" => SandboxState::Stopped,
                "error" | "cancelled" => SandboxState::Failed,
                _ => SandboxState::Starting,
            },
            error: sandbox.error,
            lease_expires_at: sandbox.archive_after,
            stopped_at: sandbox.stopped_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoatSnapshot {
    name: String,
    status: BoatSnapshotStatus,
    error: Option<String>,
    source_sandbox_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum BoatSnapshotStatus {
    Saving,
    Ready,
    Failed,
}

#[derive(Deserialize)]
struct SnapshotResponse {
    ok: bool,
    snapshot: BoatSnapshot,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageResponse {
    ok: bool,
    sandbox_id: String,
    sandbox_type: String,
    seconds: u64,
    dollars: f64,
    running: bool,
}

#[derive(Deserialize)]
struct SandboxResponse {
    ok: bool,
    sandbox: BoatSandbox,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyResponse {
    ok: bool,
    success: bool,
    #[serde(default)]
    machine_ip: Option<String>,
    ssh_user: String,
    #[serde(default)]
    ssh_endpoint: Option<String>,
    host_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandResponse {
    ok: bool,
    success: bool,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    timed_out: bool,
}

impl BoatProvider {
    pub const NAME: &str = "boat";

    pub fn new(base: &str, key: &str, org: Option<&str>) -> Result<Self> {
        let base = Url::parse(base.trim_end_matches('/')).context("invalid Boat API base URL")?;
        ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.host().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "invalid Boat API base URL"
        );
        let mut headers = header::HeaderMap::new();
        let mut auth = header::HeaderValue::from_str(&format!("Bearer {key}"))
            .context("invalid Boat API key")?;
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);
        if let Some(org) = org {
            headers.insert("x-boat-org", header::HeaderValue::from_str(org)?);
        }
        let http = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Self { http, base })
    }

    fn request(&self, method: Method, segments: &[&str]) -> RequestBuilder {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .expect("validated Boat base URL")
            .pop_if_empty()
            .extend(segments);
        self.http.request(method, url)
    }

    async fn check(response: Response, operation: &str) -> Result<Response> {
        ensure!(
            response.status().is_success(),
            "Boat {operation} returned HTTP {}",
            response.status()
        );
        Ok(response)
    }

    async fn json<T: DeserializeOwned>(response: Response, operation: &str) -> Result<T> {
        Self::check(response, operation)
            .await?
            .json()
            .await
            .with_context(|| format!("invalid Boat {operation} response"))
    }
}

#[async_trait]
impl SandboxProvider for BoatProvider {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            lease_ttl: true,
            snapshot_retention: true,
            usage_reporting: true,
            templates: true,
        }
    }

    fn guest_user(&self) -> GuestUser {
        GuestUser {
            username: "user".into(),
            home_dir: "/home/user".into(),
        }
    }

    async fn create(&self, spec: CreateSandboxSpec<'_>) -> Result<RemoteSandbox> {
        let mut body = json!({
            "type": spec.size, "noEnv": true,
            "name": sandbox_alias(spec.owner, spec.sandbox_name), "visibility": "private",
            "labels": {
                "t3fleet.managed": "true", "t3fleet.user": spec.owner, "t3fleet.sandbox": spec.sandbox_name,
            },
        });
        if let Some(ttl) = spec.lease_ttl_secs {
            body["ttlSeconds"] = json!(ttl);
        }
        if let Some(template) = spec.template {
            body["from"] = json!(template);
        }
        let response = self
            .request(Method::POST, &["sandboxes"])
            .header("Idempotency-Key", spec.idempotency_key)
            .json(&body)
            .send()
            .await
            .context("Boat create request failed")?;
        let payload: SandboxResponse = Self::json(response, "create").await?;
        ensure!(
            payload.ok
                && !payload.sandbox.id.is_empty()
                && !payload.sandbox.id.starts_with("pending:"),
            "Boat create failed"
        );
        Ok(payload.sandbox.into())
    }

    async fn get(&self, id: &str) -> Result<Option<RemoteSandbox>> {
        let response = self.request(Method::GET, &["sandboxes", id]).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let payload: SandboxResponse = Self::json(response, "status").await?;
        ensure!(
            payload.ok && payload.sandbox.id == id,
            "invalid Boat sandbox status"
        );
        Ok(Some(payload.sandbox.into()))
    }

    async fn extend_lease(&self, id: &str, ttl: u64) -> Result<()> {
        let response = self
            .request(Method::PATCH, &["sandboxes", id])
            .json(&json!({ "ttlSeconds": ttl }))
            .send()
            .await?;
        Self::check(response, "TTL extension").await?;
        Ok(())
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        let response = self
            .request(Method::POST, &["sandboxes", id, "stop"])
            .json(&json!({ "force": false }))
            .send()
            .await?;
        Self::check(response, "stop").await?;
        Ok(())
    }

    async fn resume(&self, id: &str, lease_ttl_secs: Option<u64>) -> Result<ResumeOutcome> {
        let body = match lease_ttl_secs {
            Some(ttl) => json!({ "ttlSeconds": ttl }),
            None => json!({}),
        };
        let response = self
            .request(Method::POST, &["sandboxes", id, "resume"])
            .json(&body)
            .send()
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND => return Ok(ResumeOutcome::Expired),
            StatusCode::CONFLICT => {
                let body: Value = response
                    .json()
                    .await
                    .context("invalid Boat resume conflict")?;
                if error_codes(&body).any(|code| code == "snapshot_data_expired") {
                    return Ok(ResumeOutcome::Expired);
                }
                bail!("Boat resume returned HTTP 409");
            }
            _ => {
                Self::check(response, "resume").await?;
            }
        }
        Ok(ResumeOutcome::Ready(self.wait_for(id, false).await?))
    }

    async fn save_snapshot(&self, id: &str, name: &str) -> Result<()> {
        let response = self
            .request(Method::POST, &["saved-snapshots"])
            .json(&json!({ "sandboxId": id, "name": name }))
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT
            && let Some(snapshot) = self.saved_snapshot(name).await?
            && snapshot.source_sandbox_id.as_deref() == Some(id)
        {
            return Ok(());
        }
        Self::check(response, "save snapshot").await?;
        Ok(())
    }

    async fn saved_snapshot(&self, name: &str) -> Result<Option<SavedSnapshot>> {
        let response = self
            .request(Method::GET, &["saved-snapshots", name])
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let payload: SnapshotResponse = Self::json(response, "saved snapshot status").await?;
        ensure!(
            payload.ok && payload.snapshot.name == name,
            "invalid Boat saved snapshot status"
        );
        let snapshot = payload.snapshot;
        Ok(Some(SavedSnapshot {
            status: match snapshot.status {
                BoatSnapshotStatus::Saving => SnapshotStatus::Saving,
                BoatSnapshotStatus::Ready => SnapshotStatus::Ready,
                BoatSnapshotStatus::Failed => SnapshotStatus::Failed,
            },
            error: snapshot.error,
            source_sandbox_id: snapshot.source_sandbox_id,
            created_at: snapshot.created_at,
        }))
    }

    async fn delete_saved_snapshot(&self, name: &str) -> Result<()> {
        let response = self
            .request(Method::DELETE, &["saved-snapshots", name])
            .send()
            .await?;
        if response.status() != StatusCode::NOT_FOUND {
            Self::check(response, "delete saved snapshot").await?;
        }
        Ok(())
    }

    async fn usage(&self, id: &str) -> Result<Option<SandboxUsage>> {
        let response = self
            .request(Method::GET, &["sandboxes", id, "usage"])
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let payload: UsageResponse = Self::json(response, "usage").await?;
        ensure!(
            payload.ok && payload.sandbox_id == id,
            "invalid Boat sandbox usage"
        );
        Ok(Some(SandboxUsage {
            sandbox_id: payload.sandbox_id,
            sandbox_type: payload.sandbox_type,
            seconds: payload.seconds,
            dollars: payload.dollars,
            running: payload.running,
        }))
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let response = self
            .request(Method::DELETE, &["sandboxes", id])
            .header("X-Ascii-Confirm-Delete", id)
            .send()
            .await?;
        if response.status() != StatusCode::NOT_FOUND {
            Self::check(response, "delete").await?;
        }
        Ok(())
    }

    async fn authorize_ssh(&self, id: &str, public_key: &str) -> Result<SshAccess> {
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut delay = Duration::from_millis(250);
        loop {
            let response = self
                .request(Method::POST, &["sandboxes", id, "sshkey"])
                .json(&json!({ "key": public_key }))
                .send()
                .await?;
            if response.status() == StatusCode::CONFLICT {
                let body: Value = response.json().await.unwrap_or(Value::Null);
                let transient = error_codes(&body).any(|code| TRANSIENT_SSH_ERRORS.contains(&code));
                ensure!(
                    transient && Instant::now() < deadline,
                    "Boat SSH authorization returned HTTP 409"
                );
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(4));
                continue;
            }
            let payload: KeyResponse = Self::json(response, "SSH authorization").await?;
            ensure!(
                payload.ok && payload.success,
                "Boat SSH authorization failed"
            );
            let (host, port) = match payload
                .ssh_endpoint
                .as_deref()
                .filter(|value| !value.is_empty())
            {
                Some(endpoint) => {
                    let (host, port) = endpoint
                        .rsplit_once(':')
                        .context("invalid Boat SSH endpoint")?;
                    let host = host
                        .strip_prefix('[')
                        .and_then(|host| host.strip_suffix(']'))
                        .unwrap_or(host);
                    (host.to_owned(), port.parse()?)
                }
                None => (
                    payload.machine_ip.filter(|ip| !ip.is_empty()).context(
                        "Boat SSH authorization returned neither sshEndpoint nor machineIp",
                    )?,
                    22,
                ),
            };
            ensure!(!host.is_empty() && port != 0, "invalid Boat SSH endpoint");
            return Ok(SshAccess {
                host,
                port,
                host_key: Some(payload.host_key),
                ssh_user: payload.ssh_user,
                sandbox_id: id.to_owned(),
            });
        }
    }

    async fn exec(&self, id: &str, command: &str, timeout: Duration) -> Result<String> {
        let response = self
            .request(Method::POST, &["sandboxes", id, "commands"])
            .timeout(timeout + Duration::from_secs(15))
            .json(&json!({ "command": command, "timeoutSeconds": timeout.as_secs() }))
            .send()
            .await?;
        let payload: CommandResponse = Self::json(response, "command").await?;
        ensure!(
            payload.ok && payload.success && payload.exit_code == Some(0) && !payload.timed_out,
            "Boat command failed (exit code {:?}, timed out {}){}",
            payload.exit_code,
            payload.timed_out,
            if payload.stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", payload.stderr.trim())
            }
        );
        Ok(payload.stdout)
    }
}

fn error_codes(body: &Value) -> impl Iterator<Item = &str> {
    [
        body.get("code"),
        body.get("error"),
        body.pointer("/error/code"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
}
