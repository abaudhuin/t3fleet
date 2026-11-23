mod db;
pub mod provider;
pub mod providers;
mod sandbox;

use std::{hash, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{TimeDelta, Utc};
use db::{Db, Sandbox, User};
use provider::{ProviderRegistry, SandboxProvider};
use providers::boat::BoatProvider;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use t3fleet_protocol::*;
use tokio::sync::{Mutex, MutexGuard};

pub struct Settings {
    pub db: PathBuf,
    pub boat_api_key: String,
    pub boat_org: Option<String>,
    pub boat_api_base: String,
    pub admin_token: Option<String>,
    pub idle_timeout: Duration,
    pub safety_ttl: u64,
    pub cooldown: Duration,
    pub wake_policy: WakePolicy,
    pub skip_bootstrap: bool,
    pub max_sandboxes_per_user: usize,
    pub default_template: Option<String>,
    pub snapshot_retention_days: u64,
}

pub struct App {
    db: Db,
    providers: ProviderRegistry,
    admin_hash: String,
    user_locks: [Mutex<()>; 64],
    idle_timeout: Duration,
    safety_ttl: u64,
    cooldown: Duration,
    wake_policy: WakePolicy,
    skip_bootstrap: bool,
    max_sandboxes_per_user: usize,
    default_template: Option<String>,
    snapshot_retention_days: u64,
}

pub(crate) struct ApiError(StatusCode, String);

type ApiResult<T> = Result<Json<T>, ApiError>;

impl ApiError {
    fn bad(message: &str) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }

    pub(crate) fn conflict(message: &str) -> Self {
        Self(StatusCode::CONFLICT, message.into())
    }

    fn unauthorized() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "Invalid, expired, or revoked token".into(),
        )
    }

    fn sandbox_not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "Sandbox not found".into())
    }

    fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "User not found".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorResponse { error: self.1 })).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        tracing::error!(%error, "SQLite operation failed");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database operation failed".into(),
        )
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::warn!(%error, "sandbox operation failed");
        Self(
            StatusCode::BAD_GATEWAY,
            "Sandbox operation failed; see server logs".into(),
        )
    }
}

fn token(prefix: &str) -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())
        .map(|(_, token)| token)
        .ok_or_else(ApiError::unauthorized)
}

fn validate_key(key: &str) -> Result<(), ApiError> {
    let mut parts = key.split_ascii_whitespace();
    if key.len() <= 4096
        && !key.contains(['\r', '\n', '\0'])
        && parts.next() == Some("ssh-ed25519")
        && parts.next().is_some_and(|blob| {
            blob.len() == 68
                && blob.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI")
                && blob
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/+".contains(&b))
        })
    {
        Ok(())
    } else {
        Err(ApiError::bad(
            "Expected a single OpenSSH Ed25519 public key",
        ))
    }
}

fn validate_username(username: &str) -> Result<(), ApiError> {
    if username.len() <= 48
        && username
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(ApiError::bad(
            "Username must be 1–48 lowercase letters, digits, hyphens or underscores and start with a letter or digit",
        ))
    }
}

fn sandbox_alias(owner: &str, name: &str) -> String {
    if name == DEFAULT_SANDBOX_NAME {
        format!("t3fleet-{owner}")
    } else {
        format!("t3fleet-{owner}-{name}")
    }
}

fn sandbox_name(name: Option<&str>) -> Result<&str, ApiError> {
    let name = name.unwrap_or(DEFAULT_SANDBOX_NAME);
    if !valid_sandbox_name(name) {
        return Err(ApiError::bad(
            "Sandbox name must be 1–32 lowercase letters, digits or hyphens and start with a letter or digit",
        ));
    }
    Ok(name)
}

fn valid_template(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with(sandbox::RETENTION_SNAPSHOT_PREFIX)
}

fn validate_template(template: Option<&str>) -> Result<(), ApiError> {
    if template.is_some_and(|name| !valid_template(name)) {
        return Err(ApiError::bad("Invalid or reserved saved snapshot name"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct SandboxQuery {
    sandbox: Option<String>,
    #[serde(default)]
    include_usage: bool,
}

fn expiry(ttl: u64) -> Result<chrono::DateTime<Utc>, ApiError> {
    i64::try_from(ttl)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .and_then(|delta| Utc::now().checked_add_signed(delta))
        .ok_or_else(|| ApiError::bad("Invitation TTL is too large"))
}

impl App {
    /// Returns the generated admin token only when initializing a new database.
    pub fn open(settings: Settings) -> anyhow::Result<(Arc<Self>, Option<String>)> {
        let mut providers = ProviderRegistry::new(BoatProvider::NAME);
        providers.register(Arc::new(BoatProvider::new(
            &settings.boat_api_base,
            &settings.boat_api_key,
            settings.boat_org.as_deref(),
        )?));
        Self::open_with_providers(settings, providers)
    }

    /// Opens the control plane with an explicitly configured provider registry.
    pub fn open_with_providers(
        settings: Settings,
        providers: ProviderRegistry,
    ) -> anyhow::Result<(Arc<Self>, Option<String>)> {
        let default = providers.get(providers.default_provider())?;
        ensure!(settings.safety_ttl > 0, "safety TTL must be positive");
        ensure!(
            settings.max_sandboxes_per_user > 0,
            "sandbox limit must be at least one"
        );
        ensure!(
            settings
                .default_template
                .as_deref()
                .is_none_or(valid_template),
            "invalid or reserved default template name"
        );
        ensure!(
            settings.default_template.is_none() || default.capabilities().templates,
            "default sandbox provider '{}' does not support templates",
            default.name()
        );
        let db = Db::open(&settings.db).context("opening fleet database")?;
        let provided = settings.admin_token;
        ensure!(
            provided.as_ref().is_none_or(
                |value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
            ),
            "admin token must contain only visible ASCII characters"
        );
        let candidate = provided.clone().unwrap_or_else(|| token("adm"));
        let (stored, fresh) = db.admin_hash(&token_hash(&candidate))?;
        let admin_hash = provided.as_deref().map(token_hash).unwrap_or(stored);
        Ok((
            Arc::new(Self {
                db,
                providers,
                admin_hash,
                user_locks: std::array::from_fn(|_| Mutex::new(())),
                idle_timeout: settings.idle_timeout,
                safety_ttl: settings.safety_ttl,
                cooldown: settings.cooldown,
                wake_policy: settings.wake_policy,
                skip_bootstrap: settings.skip_bootstrap,
                max_sandboxes_per_user: settings.max_sandboxes_per_user,
                default_template: settings.default_template,
                snapshot_retention_days: settings.snapshot_retention_days,
            }),
            (fresh && provided.is_none()).then_some(candidate),
        ))
    }

    fn provider(&self, sandbox: &Sandbox) -> anyhow::Result<&dyn SandboxProvider> {
        Ok(self.providers.get(&sandbox.provider)?.as_ref())
    }

    fn default_provider(&self) -> anyhow::Result<&dyn SandboxProvider> {
        Ok(self
            .providers
            .get(self.providers.default_provider())?
            .as_ref())
    }

    fn validate_provider_template(
        &self,
        provider: &dyn SandboxProvider,
        template: Option<&str>,
    ) -> Result<(), ApiError> {
        if template.is_some() && !provider.capabilities().templates {
            return Err(ApiError::bad(&format!(
                "Sandbox provider '{}' does not support templates",
                provider.name()
            )));
        }
        Ok(())
    }

    fn status(&self, user: &User, sandbox: Option<Sandbox>) -> anyhow::Result<StatusResponse> {
        let ssh_user = match &sandbox {
            Some(sandbox) => match &sandbox.ssh_user {
                Some(ssh_user) => ssh_user.clone(),
                None => self.provider(sandbox)?.guest_user().username,
            },
            None => self.default_provider()?.guest_user().username,
        };
        Ok(db::status(user, sandbox, self.wake_policy, ssh_user))
    }

    async fn sandbox_usage(&self, sandbox: &Sandbox) -> anyhow::Result<Option<SandboxUsage>> {
        let provider = self.provider(sandbox)?;
        if provider.capabilities().usage_reporting {
            provider.usage(&sandbox.provider_sandbox_id).await
        } else {
            Ok(None)
        }
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
            .route("/v1/enroll", post(enroll))
            .route("/v1/me/status", get(me_status))
            .route("/v1/me/sandboxes", get(list_sandboxes).post(create_sandbox))
            .route("/v1/me/sandboxes/{name}", delete(remove_sandbox))
            .route("/v1/me/wake", post(me_wake))
            .route("/v1/me/stop", post(me_stop))
            .route("/v1/me/ssh-ticket", post(ssh_ticket))
            .route("/v1/admin/users", get(list_users).post(create_user))
            .route("/v1/admin/usage", get(admin_usage))
            .route("/v1/admin/users/{username}", delete(delete_user))
            .route("/v1/admin/users/{username}/invite", post(invite_user))
            .route("/v1/admin/users/{username}/revoke", post(revoke_user))
            .route("/v1/admin/sandboxes/{username}/wake", post(admin_wake))
            .route("/v1/admin/sandboxes/{username}/stop", post(admin_stop))
            .with_state(self.clone())
    }

    async fn lock_user(&self, username: &str) -> MutexGuard<'_, ()> {
        self.user_locks[lock_index(username, self.user_locks.len())]
            .lock()
            .await
    }

    fn require_admin(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let hash = token_hash(bearer(headers)?);
        if bool::from(hash.as_bytes().ct_eq(self.admin_hash.as_bytes())) {
            Ok(())
        } else {
            Err(ApiError::unauthorized())
        }
    }

    async fn employee(&self, headers: &HeaderMap) -> Result<(User, MutexGuard<'_, ()>), ApiError> {
        let hash = token_hash(bearer(headers)?);
        let user = self
            .db
            .api_user(&hash)?
            .ok_or_else(ApiError::unauthorized)?;
        let guard = self.lock_user(&user.username).await;
        let user = self
            .db
            .api_user(&hash)?
            .ok_or_else(ApiError::unauthorized)?;
        self.db.touch_api_token(&hash)?;
        Ok((user, guard))
    }

    async fn admin_user(
        &self,
        headers: &HeaderMap,
        username: &str,
    ) -> Result<(User, MutexGuard<'_, ()>), ApiError> {
        self.require_admin(headers)?;
        let guard = self.lock_user(username).await;
        let user = self.db.user(username)?.ok_or_else(ApiError::not_found)?;
        Ok((user, guard))
    }

    pub async fn watch_once(&self) -> anyhow::Result<()> {
        for (username, sandbox) in self.db.watched_sandboxes()? {
            let Ok(_guard) =
                self.user_locks[lock_index(&username, self.user_locks.len())].try_lock()
            else {
                continue;
            };
            let Some(current) = self.db.sandbox_by_id(&sandbox.id)? else {
                continue;
            };
            let name = current.name.clone();
            if let Err(error) = self.watch_sandbox(current).await {
                tracing::warn!(%username, sandbox = %name, %error, "sandbox watchdog check failed");
            }
        }
        Ok(())
    }

    fn find_sandbox(&self, user: &User, name: &str) -> Result<Option<Sandbox>, ApiError> {
        let sandbox = self.db.sandbox(user, name)?;
        if sandbox.is_none() && name != DEFAULT_SANDBOX_NAME {
            return Err(ApiError::sandbox_not_found());
        }
        Ok(sandbox)
    }

    fn invitation(
        &self,
        user: &User,
        expires_at: chrono::DateTime<Utc>,
    ) -> ApiResult<InviteResponse> {
        let sandbox_id = self
            .db
            .sandbox(user, DEFAULT_SANDBOX_NAME)?
            .filter(Sandbox::provisioned)
            .map(|sandbox| sandbox.provider_sandbox_id);
        let enrollment_token = token("enr");
        self.db
            .invite(user, &token_hash(&enrollment_token), expires_at)?;
        Ok(Json(InviteResponse {
            username: user.username.clone(),
            enrollment_token,
            expires_at,
            sandbox_id,
        }))
    }

    async fn stop_user(&self, user: User, name: &str) -> ApiResult<StatusResponse> {
        let mut sandbox = self.find_sandbox(&user, name)?;
        if let Some(sandbox) = sandbox.as_mut() {
            self.stop(sandbox, "manual").await?;
        }
        Ok(Json(self.status(&user, sandbox)?))
    }

    async fn wake_user(&self, user: User, name: &str) -> ApiResult<StatusResponse> {
        let sandbox = self.ready(&user, name, WakeIntent::Explicit).await?;
        Ok(Json(self.status(&user, Some(sandbox))?))
    }
}

fn lock_index(username: &str, count: usize) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = hash::DefaultHasher::new();
    username.hash(&mut hasher);
    hasher.finish() as usize % count
}

async fn create_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> ApiResult<InviteResponse> {
    app.require_admin(&headers)?;
    validate_username(&request.username)?;
    validate_template(request.template.as_deref())?;
    app.validate_provider_template(app.default_provider()?, request.template.as_deref())?;
    expiry(request.invite_ttl_secs)?;
    let _guard = app.lock_user(&request.username).await;
    if app.db.user(&request.username)?.is_some() {
        return Err(ApiError::conflict("User already exists"));
    }
    let user = app.db.create_user(
        request.username.clone(),
        request.sandbox_size.as_str().into(),
        request.template,
    )?;
    if request.provision_now {
        app.ready(&user, DEFAULT_SANDBOX_NAME, WakeIntent::Explicit)
            .await?;
    }
    app.invitation(&user, expiry(request.invite_ttl_secs)?)
}

async fn list_users(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Vec<StatusResponse>> {
    app.require_admin(&headers)?;
    let users = app
        .db
        .users()?
        .into_iter()
        .map(|user| {
            let sandbox = app.db.sandbox(&user, DEFAULT_SANDBOX_NAME)?;
            app.status(&user, sandbox)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Json(users))
}

async fn invite_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(request): Json<InviteRequest>,
) -> ApiResult<InviteResponse> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    app.invitation(&user, expiry(request.invite_ttl_secs)?)
}

async fn revoke_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<Value> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    Ok(Json(json!({"revoked": app.db.revoke(&user)?})))
}

#[derive(Deserialize)]
struct DeleteQuery {
    #[serde(default)]
    delete_sandbox: bool,
}

async fn delete_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> ApiResult<Value> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    if query.delete_sandbox {
        for sandbox in app.db.sandboxes(&user)? {
            app.delete_sandbox(&user, sandbox).await?;
        }
    }
    app.db.delete_user(&user)?;
    Ok(Json(json!({"ok": true})))
}

async fn admin_wake(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Query(query): Query<SandboxQuery>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    app.wake_user(user, sandbox_name(query.sandbox.as_deref())?)
        .await
}

async fn admin_stop(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Query(query): Query<SandboxQuery>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    app.stop_user(user, sandbox_name(query.sandbox.as_deref())?)
        .await
}

async fn admin_usage(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Vec<AdminUsageEntry>> {
    app.require_admin(&headers)?;
    let mut entries = Vec::new();
    for (username, sandbox) in app.db.all_sandboxes()? {
        if sandbox.provisioned()
            && let Some(usage) = app.sandbox_usage(&sandbox).await?
        {
            entries.push(AdminUsageEntry {
                username,
                sandbox_name: sandbox.name,
                sandbox_id: sandbox.provider_sandbox_id,
                provider: Some(sandbox.provider),
                state: sandbox.state.as_str().into(),
                usage,
            });
        }
    }
    Ok(Json(entries))
}

async fn enroll(
    State(app): State<Arc<App>>,
    Json(request): Json<EnrollRequest>,
) -> ApiResult<EnrollResponse> {
    let hash = token_hash(&request.token);
    let user = app
        .db
        .enrollment_user(&hash)?
        .ok_or_else(ApiError::unauthorized)?;
    validate_key(&request.ssh_public_key)?;
    if request.device_name.trim().is_empty() || request.device_name.len() > 255 {
        return Err(ApiError::bad("Device name must be 1–255 bytes"));
    }
    let _guard = app.lock_user(&user.username).await;
    if app.db.enrollment_user(&hash)?.is_none() {
        return Err(ApiError::unauthorized());
    }
    let mut sandbox = app.prepare_enrollment(&user).await?;
    if !app.db.claim_enrollment(&user, &hash)? {
        return Err(ApiError::unauthorized());
    }
    let provider = app.provider(&sandbox)?;
    let ssh_user = if sandbox.state.is_stopped() {
        sandbox
            .ssh_user
            .unwrap_or_else(|| provider.guest_user().username)
    } else {
        let access = provider
            .authorize_ssh(&sandbox.provider_sandbox_id, &request.ssh_public_key)
            .await?;
        sandbox.ssh_user = Some(access.ssh_user.clone());
        app.db.save_sandbox(&sandbox)?;
        access.ssh_user
    };
    let api_token = token("usr");
    app.db.finish_enrollment(
        &user,
        &request.ssh_public_key,
        &request.device_name,
        &token_hash(&api_token),
    )?;
    Ok(Json(EnrollResponse {
        username: user.username,
        api_token,
        ssh_alias: sandbox.alias,
        sandbox_id: sandbox.provider_sandbox_id,
        ssh_user,
    }))
}

async fn me_status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SandboxQuery>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    let sandbox = app.find_sandbox(&user, sandbox_name(query.sandbox.as_deref())?)?;
    Ok(Json(
        app.sandbox_status(&user, sandbox, query.include_usage)
            .await?,
    ))
}

async fn me_wake(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SandboxQuery>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    app.wake_user(user, sandbox_name(query.sandbox.as_deref())?)
        .await
}

async fn me_stop(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SandboxQuery>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    app.stop_user(user, sandbox_name(query.sandbox.as_deref())?)
        .await
}

async fn list_sandboxes(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SandboxQuery>,
) -> ApiResult<Vec<StatusResponse>> {
    let (user, _guard) = app.employee(&headers).await?;
    let mut statuses = Vec::new();
    for sandbox in app.db.sandboxes(&user)? {
        let status = if query.include_usage {
            app.sandbox_status(&user, Some(sandbox), true).await?
        } else {
            app.status(&user, Some(sandbox))?
        };
        statuses.push(status);
    }
    Ok(Json(statuses))
}

async fn create_sandbox(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateSandboxRequest>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    let name = sandbox_name(Some(&request.name))?;
    if name == DEFAULT_SANDBOX_NAME {
        return Err(ApiError::bad(
            "The default sandbox is provisioned by enrollment or wake",
        ));
    }
    validate_template(request.template.as_deref())?;
    let size = request.size.map(SandboxSize::as_str).unwrap_or(&user.size);
    let template = request
        .template
        .as_deref()
        .or(app.default_template.as_deref());
    let existing = app.db.sandbox(&user, name)?;
    let provider = match &existing {
        Some(sandbox) => app.provider(sandbox)?,
        None => app.default_provider()?,
    };
    app.validate_provider_template(provider, template)?;
    let sandbox = if let Some(existing) = existing {
        if existing.provisioned()
            || existing.size != size
            || existing.template.as_deref() != template
        {
            return Err(ApiError::conflict("Sandbox name is already in use"));
        }
        existing
    } else {
        if app.db.sandboxes(&user)?.len() >= app.max_sandboxes_per_user {
            return Err(ApiError::conflict("Sandbox limit reached"));
        }
        app.db
            .reserve_sandbox(
                &user,
                name,
                size,
                template,
                app.providers.default_provider(),
            )?
            .ok_or_else(|| ApiError::conflict("SSH alias is already in use"))?
    };
    let sandbox = app
        .start_sandbox(&user, sandbox, WakeIntent::Explicit)
        .await?;
    Ok(Json(app.status(&user, Some(sandbox))?))
}

async fn remove_sandbox(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Value> {
    let (user, _guard) = app.employee(&headers).await?;
    let name = sandbox_name(Some(&name))?;
    if name == DEFAULT_SANDBOX_NAME {
        return Err(ApiError::bad("The default sandbox cannot be deleted"));
    }
    let sandbox = app
        .db
        .sandbox(&user, name)?
        .ok_or_else(ApiError::sandbox_not_found)?;
    app.delete_sandbox(&user, sandbox).await?;
    Ok(Json(json!({"ok": true})))
}

async fn ssh_ticket(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<SshTicketRequest>,
) -> ApiResult<SshTicketResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    validate_key(&request.ssh_public_key)?;
    let mut sandbox = app
        .ready(
            &user,
            sandbox_name(request.sandbox_name.as_deref())?,
            request.intent,
        )
        .await?;
    let access = app
        .provider(&sandbox)?
        .authorize_ssh(&sandbox.provider_sandbox_id, &request.ssh_public_key)
        .await?;
    sandbox.ssh_user = Some(access.ssh_user.clone());
    app.record_activity(&mut sandbox)?;
    Ok(Json(SshTicketResponse {
        host: access.host,
        port: access.port,
        ssh_user: access.ssh_user,
        host_key: access.host_key,
        sandbox_id: access.sandbox_id,
    }))
}
