use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const T3_PORT: u16 = 3773;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxSize {
    #[default]
    Small,
    Default,
    Large,
    Xlarge,
}

impl SandboxSize {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Default => "default",
            Self::Large => "large",
            Self::Xlarge => "xlarge",
        }
    }
}

pub const fn default_invite_ttl() -> u64 {
    86400
}

const fn provision_by_default() -> bool {
    true
}

#[derive(Deserialize, Serialize)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(default)]
    pub sandbox_size: SandboxSize,
    #[serde(default = "provision_by_default")]
    pub provision_now: bool,
    #[serde(default = "default_invite_ttl")]
    pub invite_ttl_secs: u64,
}

#[derive(Deserialize, Serialize)]
pub struct InviteRequest {
    #[serde(default = "default_invite_ttl")]
    pub invite_ttl_secs: u64,
}

#[derive(Deserialize, Serialize)]
pub struct InviteResponse {
    pub username: String,
    pub enrollment_token: String,
    pub expires_at: DateTime<Utc>,
    pub sandbox_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct EnrollRequest {
    pub token: String,
    pub ssh_public_key: String,
    pub device_name: String,
}

#[derive(Deserialize, Serialize)]
pub struct EnrollResponse {
    pub username: String,
    pub api_token: String,
    pub ssh_alias: String,
    pub sandbox_id: String,
    pub server_t3_port: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WakePolicy {
    #[default]
    Auto,
    AggressiveIdle,
    Explicit,
}

impl WakePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::AggressiveIdle => "aggressive-idle",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SandboxActivity {
    #[serde(default)]
    pub active_turns: u64,
    #[serde(default)]
    pub active_sessions: u64,
    #[serde(default)]
    pub streaming_messages: u64,
    #[serde(default)]
    pub provider_procs: u64,
    #[serde(default)]
    pub interactive_ptys: u64,
    #[serde(default)]
    pub ssh_conns: u64,
    #[serde(default)]
    pub t3_http_conns: u64,
    #[serde(default)]
    pub latest_t3_activity_at: Option<DateTime<Utc>>,
}

impl SandboxActivity {
    pub fn has_active_work(&self) -> bool {
        self.active_turns > 0
            || self.active_sessions > 0
            || self.streaming_messages > 0
            || self.provider_procs > 0
            || self.interactive_ptys > 0
    }

    pub fn has_connections(&self) -> bool {
        self.ssh_conns > 0 || self.t3_http_conns > 0
    }
}

#[derive(Deserialize, Serialize)]
pub struct StatusResponse {
    pub username: String,
    pub sandbox_size: String,
    #[serde(default)]
    pub sandbox_name: Option<String>,
    pub sandbox_id: Option<String>,
    pub ssh_alias: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub wake_policy: WakePolicy,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub stopped_reason: Option<String>,
    #[serde(default)]
    pub activity: Option<SandboxActivity>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WakeIntent {
    SshProxy,
    Explicit,
}

#[derive(Deserialize, Serialize)]
pub struct SshTicketRequest {
    pub ssh_public_key: String,
    pub intent: WakeIntent,
}

#[derive(Deserialize, Serialize)]
pub struct SshTicketResponse {
    pub host: String,
    pub port: u16,
    pub host_key: String,
    pub ssh_user: String,
    pub sandbox_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct PairRequest {
    pub local_port: u16,
    pub label: String,
}

#[derive(Deserialize, Serialize)]
pub struct PairResponse {
    pub pair_url: String,
    pub t3_deep_link: String,
    pub credential: String,
    pub expires_at: DateTime<Utc>,
    pub local_port: u16,
    pub ssh_alias: String,
}

#[derive(Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
