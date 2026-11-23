use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode, Url, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use t3fleet_protocol::SshTicketResponse;
use tokio::time::{Instant, sleep};

use crate::db::User;

const TRANSIENT_SSH_ERRORS: &[&str] = &[
    "sandbox_restoring",
    "sandbox_securing",
    "sandbox_starting",
    "machine_not_running",
];

pub struct Boat {
    http: Client,
    base: Url,
}

#[derive(Deserialize)]
pub struct RemoteSandbox {
    pub id: String,
    pub state: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "archiveAfter")]
    pub archive_after: Option<DateTime<Utc>>,
    #[serde(rename = "stoppedAt")]
    pub stopped_at: Option<DateTime<Utc>>,
}

impl RemoteSandbox {
    pub fn running(&self) -> bool {
        matches!(self.state.as_str(), "ready" | "idle" | "running")
    }

    pub fn stopping(&self) -> bool {
        matches!(self.state.as_str(), "archiving" | "stopping")
    }
}

#[derive(Deserialize)]
struct SandboxResponse {
    ok: bool,
    sandbox: RemoteSandbox,
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

impl Boat {
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

    fn request(&self, method: Method, id: Option<&str>, action: Option<&str>) -> RequestBuilder {
        let mut url = self.base.clone();
        {
            let mut path = url.path_segments_mut().expect("validated Boat base URL");
            path.pop_if_empty().push("sandboxes");
            if let Some(id) = id {
                path.push(id);
            }
            if let Some(action) = action {
                path.push(action);
            }
        }
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

    pub async fn create(&self, user: &User, ttl: u64) -> Result<RemoteSandbox> {
        let response = self
            .request(Method::POST, None, None)
            .header("Idempotency-Key", &user.id)
            .json(&json!({
                "type": user.size, "noEnv": true, "ttlSeconds": ttl,
                "name": format!("t3fleet-{}", user.username),
                "labels": { "t3fleet.managed": "true", "t3fleet.user": user.username },
            }))
            .send()
            .await
            .context("Boat create request failed")?;
        let payload: SandboxResponse = Self::json(response, "create").await?;
        ensure!(
            payload.ok && !payload.sandbox.id.is_empty(),
            "Boat create failed"
        );
        Ok(payload.sandbox)
    }

    pub async fn get(&self, id: &str) -> Result<RemoteSandbox> {
        let response = self.request(Method::GET, Some(id), None).send().await?;
        let payload: SandboxResponse = Self::json(response, "status").await?;
        ensure!(
            payload.ok && payload.sandbox.id == id,
            "invalid Boat sandbox status"
        );
        Ok(payload.sandbox)
    }

    pub async fn wait_for(&self, id: &str, archived: bool) -> Result<RemoteSandbox> {
        tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                let sandbox = self.get(id).await?;
                if (archived && sandbox.state == "archived") || (!archived && sandbox.running()) {
                    return Ok(sandbox);
                }
                if matches!(sandbox.state.as_str(), "error" | "cancelled") {
                    bail!(
                        "Boat sandbox entered terminal state '{}'{}",
                        sandbox.state,
                        sandbox
                            .error
                            .as_deref()
                            .map(|msg| format!(": {msg}"))
                            .unwrap_or_default()
                    );
                }
                sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .context("timed out waiting for Boat sandbox")?
    }

    pub async fn ttl(&self, id: &str, ttl: u64) -> Result<()> {
        let response = self
            .request(Method::PATCH, Some(id), None)
            .json(&json!({ "ttlSeconds": ttl }))
            .send()
            .await?;
        Self::check(response, "TTL extension").await?;
        Ok(())
    }

    pub async fn request_stop(&self, id: &str) -> Result<()> {
        let response = self
            .request(Method::POST, Some(id), Some("stop"))
            .json(&json!({ "force": false }))
            .send()
            .await?;
        Self::check(response, "stop").await?;
        Ok(())
    }

    pub async fn resume(&self, id: &str, ttl: u64) -> Result<RemoteSandbox> {
        let response = self
            .request(Method::POST, Some(id), Some("resume"))
            .json(&json!({ "ttlSeconds": ttl }))
            .send()
            .await?;
        Self::check(response, "resume").await?;
        self.wait_for(id, false).await
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        let response = self
            .request(Method::DELETE, Some(id), None)
            .header("X-Ascii-Confirm-Delete", id)
            .send()
            .await?;
        if response.status() != StatusCode::NOT_FOUND {
            Self::check(response, "delete").await?;
        }
        Ok(())
    }

    pub async fn authorize_key(&self, id: &str, key: &str) -> Result<SshTicketResponse> {
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut delay = Duration::from_millis(250);
        loop {
            let response = self
                .request(Method::POST, Some(id), Some("sshkey"))
                .json(&json!({ "key": key }))
                .send()
                .await?;
            if response.status() == StatusCode::CONFLICT {
                let body: Value = response.json().await.unwrap_or(Value::Null);
                let transient = [
                    body.get("code"),
                    body.get("error"),
                    body.pointer("/error/code"),
                ]
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|code| TRANSIENT_SSH_ERRORS.contains(&code));
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
            return Ok(SshTicketResponse {
                host,
                port,
                host_key: payload.host_key,
                ssh_user: payload.ssh_user,
                sandbox_id: id.to_owned(),
            });
        }
    }

    pub async fn command(&self, id: &str, command: &str, timeout: u64) -> Result<String> {
        let response = self
            .request(Method::POST, Some(id), Some("commands"))
            .timeout(Duration::from_secs(timeout + 15))
            .json(&json!({ "command": command, "timeoutSeconds": timeout }))
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
