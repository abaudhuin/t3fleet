mod boat;
mod db;
mod sandbox;

use std::{hash, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use boat::Boat;
use chrono::{TimeDelta, Utc};
use db::{Db, User};
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
}

pub struct App {
    db: Db,
    boat: Boat,
    admin_hash: String,
    user_locks: [Mutex<()>; 64],
    idle_timeout: Duration,
    safety_ttl: u64,
    cooldown: Duration,
    wake_policy: WakePolicy,
    skip_bootstrap: bool,
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
        ensure!(settings.safety_ttl > 0, "safety TTL must be positive");
        let boat = Boat::new(
            &settings.boat_api_base,
            &settings.boat_api_key,
            settings.boat_org.as_deref(),
        )?;
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
                boat,
                admin_hash,
                user_locks: std::array::from_fn(|_| Mutex::new(())),
                idle_timeout: settings.idle_timeout,
                safety_ttl: settings.safety_ttl,
                cooldown: settings.cooldown,
                wake_policy: settings.wake_policy,
                skip_bootstrap: settings.skip_bootstrap,
            }),
            (fresh && provided.is_none()).then_some(candidate),
        ))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
            .route("/v1/enroll", post(enroll))
            .route("/v1/me/status", get(me_status))
            .route("/v1/me/wake", post(me_wake))
            .route("/v1/me/stop", post(me_stop))
            .route("/v1/me/ssh-ticket", post(ssh_ticket))
            .route("/v1/me/pair", post(pair))
            .route("/v1/admin/users", get(list_users).post(create_user))
            .route(
                "/v1/admin/users/{username}",
                axum::routing::delete(delete_user),
            )
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
        for user in self.db.users(true)? {
            let Ok(_guard) =
                self.user_locks[lock_index(&user.username, self.user_locks.len())].try_lock()
            else {
                continue;
            };
            if let Err(error) = self.check_idle(&user).await {
                tracing::warn!(username = %user.username, %error, "idle check failed");
            }
        }
        Ok(())
    }

    fn invitation(
        &self,
        user: &User,
        expires_at: chrono::DateTime<Utc>,
    ) -> ApiResult<InviteResponse> {
        let sandbox_id = self.db.sandbox(user)?.map(|sandbox| sandbox.boat_id);
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

    async fn stop_user(&self, user: User) -> ApiResult<StatusResponse> {
        if let Some(mut sandbox) = self.db.sandbox(&user)? {
            self.stop(&mut sandbox, "manual").await?;
        }
        Ok(Json(self.db.status(user, self.wake_policy)?))
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
    expiry(request.invite_ttl_secs)?;
    let _guard = app.lock_user(&request.username).await;
    if app.db.user(&request.username)?.is_some() {
        return Err(ApiError::conflict("User already exists"));
    }
    let user = app.db.create_user(
        request.username.clone(),
        request.sandbox_size.as_str().into(),
    )?;
    if request.provision_now {
        app.ready(&user, WakeIntent::Explicit).await?;
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
        .users(false)?
        .into_iter()
        .map(|user| app.db.status(user, app.wake_policy))
        .collect::<Result<Vec<_>, _>>()?;
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
    if query.delete_sandbox
        && let Some(sandbox) = app.db.sandbox(&user)?
    {
        app.boat.delete(&sandbox.boat_id).await?;
    }
    app.db.delete_user(&user)?;
    Ok(Json(json!({"ok": true})))
}

async fn admin_wake(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    app.ready(&user, WakeIntent::Explicit).await?;
    Ok(Json(app.db.status(user, app.wake_policy)?))
}

async fn admin_stop(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.admin_user(&headers, &username).await?;
    app.stop_user(user).await
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
    let sandbox = app.prepare_enrollment(&user).await?;
    if !app.db.claim_enrollment(&user, &hash)? {
        return Err(ApiError::unauthorized());
    }
    if sandbox.state != "archived" {
        app.boat
            .authorize_key(&sandbox.boat_id, &request.ssh_public_key)
            .await?;
    }
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
        sandbox_id: sandbox.boat_id,
        server_t3_port: T3_PORT,
    }))
}

async fn me_status(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    Ok(Json(app.status(user).await?))
}

async fn me_wake(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    app.ready(&user, WakeIntent::Explicit).await?;
    Ok(Json(app.db.status(user, app.wake_policy)?))
}

async fn me_stop(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<StatusResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    app.stop_user(user).await
}

async fn ssh_ticket(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<SshTicketRequest>,
) -> ApiResult<SshTicketResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    validate_key(&request.ssh_public_key)?;
    let mut sandbox = app.ready(&user, request.intent).await?;
    let response = app
        .boat
        .authorize_key(&sandbox.boat_id, &request.ssh_public_key)
        .await?;
    app.record_activity(&mut sandbox)?;
    Ok(Json(response))
}

async fn pair(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PairRequest>,
) -> ApiResult<PairResponse> {
    let (user, _guard) = app.employee(&headers).await?;
    if request.local_port == 0
        || request.label.trim().is_empty()
        || request.label.len() > 255
        || request.label.chars().any(char::is_control)
    {
        return Err(ApiError::bad(
            "Pairing requires a nonzero local port and a printable label of 1–255 bytes",
        ));
    }
    let sandbox = app.ready(&user, WakeIntent::Explicit).await?;
    Ok(Json(app.pairing(&sandbox, request).await?))
}
