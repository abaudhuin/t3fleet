use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use t3fleet_protocol::SandboxUsage;
use tokio::time::sleep;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderCapabilities {
    pub lease_ttl: bool,
    pub snapshot_retention: bool,
    pub usage_reporting: bool,
    pub templates: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestUser {
    pub username: String,
    pub home_dir: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl SandboxState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    pub fn is_running(self) -> bool {
        self == Self::Running
    }

    pub fn is_stopping(self) -> bool {
        self == Self::Stopping
    }

    pub fn is_stopped(self) -> bool {
        self == Self::Stopped
    }
}

#[derive(Clone, Debug)]
pub struct RemoteSandbox {
    pub id: String,
    pub state: SandboxState,
    pub error: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct CreateSandboxSpec<'a> {
    pub owner: &'a str,
    pub sandbox_name: &'a str,
    pub size: &'a str,
    pub template: Option<&'a str>,
    pub lease_ttl_secs: Option<u64>,
    /// Retries of the same create use the same key.
    pub idempotency_key: &'a str,
}

pub enum ResumeOutcome {
    Ready(RemoteSandbox),
    /// The provider has discarded the stopped sandbox's disk.
    Expired,
}

#[derive(Clone, Debug)]
pub struct SavedSnapshot {
    pub status: SnapshotStatus,
    pub error: Option<String>,
    pub source_sandbox_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

impl SavedSnapshot {
    pub fn belongs_to(&self, id: &str) -> bool {
        self.source_sandbox_id
            .as_deref()
            .is_none_or(|source| source == id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotStatus {
    Saving,
    Ready,
    Failed,
}

#[derive(Clone, Debug)]
pub struct SshAccess {
    pub host: String,
    pub port: u16,
    pub ssh_user: String,
    /// An authenticated host key from the provider, if available.
    pub host_key: Option<String>,
    pub sandbox_id: String,
}

#[async_trait]
pub trait SandboxProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> ProviderCapabilities;
    fn guest_user(&self) -> GuestUser;

    async fn create(&self, spec: CreateSandboxSpec<'_>) -> Result<RemoteSandbox>;
    async fn get(&self, id: &str) -> Result<Option<RemoteSandbox>>;

    async fn wait_for(&self, id: &str, stopped: bool) -> Result<RemoteSandbox> {
        let name = self.name();
        let desired = if stopped {
            SandboxState::Stopped
        } else {
            SandboxState::Running
        };
        tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                let sandbox = self
                    .get(id)
                    .await?
                    .with_context(|| format!("{name} sandbox {id} not found"))?;
                if sandbox.state == desired {
                    return Ok(sandbox);
                }
                if sandbox.state == SandboxState::Failed {
                    bail!(
                        "{name} sandbox {id} failed{}",
                        sandbox
                            .error
                            .as_deref()
                            .map(|message| format!(": {message}"))
                            .unwrap_or_default()
                    );
                }
                sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "timed out waiting for {name} sandbox {id} to be {}",
                desired.as_str()
            )
        })?
    }

    async fn resume(&self, id: &str, lease_ttl_secs: Option<u64>) -> Result<ResumeOutcome>;
    async fn suspend(&self, id: &str) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn authorize_ssh(&self, id: &str, public_key: &str) -> Result<SshAccess>;
    async fn exec(&self, id: &str, command: &str, timeout: Duration) -> Result<String>;

    async fn extend_lease(&self, _id: &str, _lease_ttl_secs: u64) -> Result<()> {
        Ok(())
    }

    async fn usage(&self, _id: &str) -> Result<Option<SandboxUsage>> {
        Ok(None)
    }

    async fn save_snapshot(&self, _id: &str, _name: &str) -> Result<()> {
        bail!(
            "provider '{}' does not support saved snapshots",
            self.name()
        )
    }

    async fn saved_snapshot(&self, _name: &str) -> Result<Option<SavedSnapshot>> {
        Ok(None)
    }

    async fn delete_saved_snapshot(&self, _name: &str) -> Result<()> {
        Ok(())
    }
}

pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn SandboxProvider>>,
    default_provider: String,
}

impl ProviderRegistry {
    pub fn new(default_provider: impl Into<String>) -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: default_provider.into(),
        }
    }

    pub fn register(&mut self, provider: Arc<dyn SandboxProvider>) {
        self.providers.insert(provider.name().into(), provider);
    }

    pub fn get(&self, name: &str) -> Result<&Arc<dyn SandboxProvider>> {
        self.providers
            .get(name)
            .with_context(|| format!("unknown sandbox provider '{name}'"))
    }

    pub fn default_provider(&self) -> &str {
        &self.default_provider
    }
}
