use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    process::{Output, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
};
use chrono::{TimeDelta, Utc};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use t3fleet_protocol::{
    EnrollResponse, InviteResponse, PairResponse, SshTicketResponse, StatusResponse, WakePolicy,
};
use t3fleet_server::{App, Settings};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    task::JoinHandle,
    time::timeout,
};

const ADMIN: &str = "fleet-admin-secret";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f fleet-test";

#[derive(Clone, Copy, Default)]
enum Activity {
    #[default]
    Idle,
    IdleTunnelOnly,
    Active,
    Failed,
}

#[derive(Default)]
struct Machine {
    state: &'static str,
    activity: Activity,
    archive_after: Option<String>,
    stopped_at: Option<String>,
}

struct Call {
    method: Method,
    path: String,
    body: Value,
    idempotency: Option<String>,
    confirm_delete: Option<String>,
}

#[derive(Default)]
struct BoatMock {
    machines: HashMap<String, Machine>,
    calls: Vec<Call>,
    endpoint: Option<SocketAddr>,
    transient_keys: usize,
    fail_create_response: bool,
}

impl BoatMock {
    fn count(&self, method: Method, path: &str) -> usize {
        self.calls
            .iter()
            .filter(|call| call.method == method && call.path == path)
            .count()
    }
}

async fn mock_boat(
    State(boat): State<Arc<Mutex<BoatMock>>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map_or(Value::Null, |Json(body)| body);
    let get_header = |name| headers.get(name).and_then(|value| value.to_str().ok());
    assert_eq!(get_header("authorization"), Some("Bearer mock-boat"));
    assert_eq!(get_header("x-boat-org"), Some("mock-org"));
    let path = uri
        .path()
        .strip_prefix("/api/v1")
        .expect("Boat v1 API path");
    let mut boat = boat.lock().unwrap();
    boat.calls.push(Call {
        method: method.clone(),
        path: path.into(),
        body: body.clone(),
        idempotency: get_header("idempotency-key").map(str::to_owned),
        confirm_delete: get_header("x-ascii-confirm-delete").map(str::to_owned),
    });

    let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
    let (status, payload) = match (method, segments.as_slice()) {
        (Method::POST, ["sandboxes"]) => {
            let username = body["labels"]["t3fleet.user"].as_str().unwrap();
            let id = format!("bx_{username}");
            assert_eq!(body["noEnv"], true);
            assert_eq!(body["ttlSeconds"], 7200);
            assert_eq!(body["name"], format!("t3fleet-{username}"));
            assert_eq!(body["labels"]["t3fleet.managed"], "true");
            assert_eq!(get_header("idempotency-key").unwrap().len(), 36);
            boat.machines.entry(id.clone()).or_insert_with(|| Machine {
                state: "ready",
                ..Machine::default()
            });
            if std::mem::take(&mut boat.fail_create_response) {
                (StatusCode::SERVICE_UNAVAILABLE, json!({"ok": false}))
            } else {
                (
                    StatusCode::ACCEPTED,
                    json!({"ok": true, "sandbox": {"id": id, "state": "starting"}}),
                )
            }
        }
        (Method::GET, ["sandboxes", id]) => {
            let machine = &boat.machines[*id];
            (
                StatusCode::OK,
                json!({
                    "ok": true, "sandbox": {"id": id, "state": machine.state,
                    "archiveAfter": machine.archive_after, "stoppedAt": machine.stopped_at}
                }),
            )
        }
        (Method::PATCH, ["sandboxes", id]) => {
            assert_eq!(body, json!({"ttlSeconds": 7200}));
            boat.machines.get_mut(*id).unwrap().archive_after =
                Some((Utc::now() + TimeDelta::hours(2)).to_rfc3339());
            (StatusCode::OK, json!({"ok": true}))
        }
        (Method::POST, ["sandboxes", id, "stop"]) => {
            assert_eq!(body, json!({"force": false}));
            let machine = boat.machines.get_mut(*id).unwrap();
            machine.state = "archived";
            machine.stopped_at = Some(Utc::now().to_rfc3339());
            (StatusCode::ACCEPTED, json!({"ok": true}))
        }
        (Method::POST, ["sandboxes", id, "resume"]) => {
            assert_eq!(body, json!({"ttlSeconds": 7200}));
            let machine = boat.machines.get_mut(*id).unwrap();
            assert_eq!(machine.state, "archived");
            machine.state = "running";
            machine.stopped_at = None;
            (StatusCode::ACCEPTED, json!({"ok": true}))
        }
        (Method::DELETE, ["sandboxes", id]) => {
            assert_eq!(get_header("x-ascii-confirm-delete"), Some(*id));
            assert!(boat.machines.remove(*id).is_some());
            (StatusCode::ACCEPTED, json!({"ok": true}))
        }
        (Method::POST, ["sandboxes", id, "sshkey"]) => {
            assert_ne!(boat.machines[*id].state, "archived");
            assert!(body["key"].as_str().unwrap().starts_with("ssh-ed25519 "));
            if boat.transient_keys > 0 {
                boat.transient_keys -= 1;
                (
                    StatusCode::CONFLICT,
                    json!({"ok": false, "error": {"code": "sandbox_restoring"}}),
                )
            } else {
                (
                    StatusCode::OK,
                    json!({
                        "ok": true, "success": true, "machineIp": "127.0.0.1", "sshUser": "user",
                        "sshEndpoint": boat.endpoint.map(|address| address.to_string()),
                        "hostKey": KEY,
                    }),
                )
            }
        }
        (Method::POST, ["sandboxes", id, "commands"]) => {
            let command = body["command"].as_str().unwrap();
            let stdout = if command.contains("ssh_conns") {
                assert_eq!(body["timeoutSeconds"], 15);
                assert!(command.contains("sport = :22") && command.contains("sport = :3773"));
                match boat.machines[*id].activity {
                    Activity::Idle => json!({
                        "active_turns": 0, "active_sessions": 0, "streaming_messages": 0,
                        "provider_procs": 0, "interactive_ptys": 0, "ssh_conns": 0,
                        "t3_http_conns": 0, "latest_t3_activity_at": null
                    })
                    .to_string(),
                    Activity::IdleTunnelOnly => json!({
                        "active_turns": 0, "active_sessions": 0, "streaming_messages": 0,
                        "provider_procs": 0, "interactive_ptys": 0, "ssh_conns": 1,
                        "t3_http_conns": 1, "latest_t3_activity_at": null
                    })
                    .to_string(),
                    Activity::Active => json!({
                        "active_turns": 1, "active_sessions": 1, "streaming_messages": 0,
                        "provider_procs": 1, "interactive_ptys": 0, "ssh_conns": 0,
                        "t3_http_conns": 0, "latest_t3_activity_at": null
                    })
                    .to_string(),
                    Activity::Failed => {
                        return (StatusCode::BAD_GATEWAY, Json(json!({"ok": false})));
                    }
                }
            } else if command.contains("auth pairing create") {
                assert_eq!(body["timeoutSeconds"], 300);
                json!({
                    "credential": "pair&secret",
                    "pairUrl": "http://127.0.0.1:13773/pair#token=pair%26secret",
                    "expiresAt": Utc::now() + TimeDelta::minutes(15),
                })
                .to_string()
            } else {
                assert_eq!(body["timeoutSeconds"], 300);
                assert!(command.contains("systemctl enable --now t3code"));
                String::new()
            };
            (
                StatusCode::OK,
                json!({
                    "ok": true, "success": true, "exitCode": 0,
                    "stdout": stdout, "stderr": "", "timedOut": false,
                }),
            )
        }
        _ => panic!("unexpected Boat request to {path}"),
    };
    (status, Json(payload))
}

struct Fleet {
    temp: TempDir,
    boat: Arc<Mutex<BoatMock>>,
    boat_url: String,
    app: Arc<App>,
    server_url: String,
    http: Client,
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn serve(router: Router) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

fn settings_with_policy(
    temp: &TempDir,
    boat_url: &str,
    bootstrap: bool,
    wake_policy: WakePolicy,
) -> Settings {
    Settings {
        db: temp.path().join("fleet.sqlite"),
        boat_api_key: "mock-boat".into(),
        boat_org: Some("mock-org".into()),
        boat_api_base: format!("{boat_url}/api/v1"),
        admin_token: Some(ADMIN.into()),
        idle_timeout: Duration::ZERO,
        safety_ttl: 7200,
        cooldown: Duration::from_secs(120),
        wake_policy,
        skip_bootstrap: !bootstrap,
    }
}

fn settings(temp: &TempDir, boat_url: &str, bootstrap: bool) -> Settings {
    settings_with_policy(temp, boat_url, bootstrap, WakePolicy::Auto)
}

impl Fleet {
    async fn start(bootstrap: bool) -> Self {
        Self::start_with_policy(bootstrap, WakePolicy::Auto).await
    }

    async fn start_with_policy(bootstrap: bool, wake_policy: WakePolicy) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let boat = Arc::new(Mutex::new(BoatMock::default()));
        let (boat_url, boat_task) =
            serve(Router::new().fallback(mock_boat).with_state(boat.clone())).await;
        let (app, generated) = App::open(settings_with_policy(
            &temp,
            &boat_url,
            bootstrap,
            wake_policy,
        ))
        .unwrap();
        assert!(generated.is_none());
        let (server_url, server_task) = serve(app.router()).await;
        let http = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            temp,
            boat,
            boat_url,
            app,
            server_url,
            http,
            tasks: [boat_task, server_task],
        }
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.server_url))
    }

    fn admin(&self, method: Method, path: &str) -> RequestBuilder {
        self.request(method, path).bearer_auth(ADMIN)
    }

    async fn invite(&self, username: &str, provision: bool) -> InviteResponse {
        ok(self.admin(Method::POST, "/v1/admin/users").json(&json!({
            "username": username, "provision_now": provision,
        })))
        .await
    }

    fn enroll(&self, token: &str, device: &str) -> RequestBuilder {
        self.request(Method::POST, "/v1/enroll")
            .json(&json!({"token": token, "ssh_public_key": KEY, "device_name": device}))
    }

    async fn employee(&self, username: &str, provision: bool) -> EnrollResponse {
        let invite = self.invite(username, provision).await;
        ok(self.enroll(&invite.enrollment_token, "test-device")).await
    }

    fn me(&self, employee: &EnrollResponse, method: Method, path: &str) -> RequestBuilder {
        self.request(method, path).bearer_auth(&employee.api_token)
    }

    fn cli(&self) -> Command {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_t3fleet"));
        cli.env("HOME", self.temp.path())
            .env("XDG_CONFIG_HOME", self.temp.path())
            .env("NO_PROXY", "127.0.0.1")
            .env_remove("T3FLEET_CONFIG")
            .env_remove("T3FLEET_SSH_CONFIG")
            .env_remove("T3FLEET_WAKE_INTENT")
            .kill_on_drop(true);
        cli
    }
}

async fn ok<T: DeserializeOwned>(request: RequestBuilder) -> T {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "HTTP {status}: {body}");
    serde_json::from_str(&body).unwrap()
}

async fn rejected(request: RequestBuilder, expected: StatusCode) -> String {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, expected, "{body}");
    body
}

#[tokio::test]
async fn invitation_expiry_single_use_and_device_revocation() {
    let fleet = Fleet::start(false).await;
    let health: Value = ok(fleet.request(Method::GET, "/healthz")).await;
    assert_eq!(health, json!({"ok": true}));
    rejected(
        fleet.request(Method::GET, "/v1/admin/users"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let invite: InviteResponse = ok(fleet.admin(Method::POST, "/v1/admin/users").json(&json!({
        "username": "alice",
    })))
    .await;
    assert_eq!(invite.sandbox_id.as_deref(), Some("bx_alice"));
    assert!(invite.enrollment_token.starts_with("enr_"));

    let expired: InviteResponse = ok(fleet
        .admin(Method::POST, "/v1/admin/users/alice/invite")
        .json(&json!({"invite_ttl_secs": 0})))
    .await;
    rejected(
        fleet.enroll(&expired.enrollment_token, "expired"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    rejected(
        fleet.enroll("invented", "invalid"),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let token = &invite.enrollment_token;
    let first = fleet.enroll(token, "first").send();
    let concurrent = fleet.enroll(token, "concurrent").send();
    let (first, concurrent) = tokio::join!(first, concurrent);
    let (first, concurrent) = (first.unwrap(), concurrent.unwrap());
    let (accepted, reused) = if first.status().is_success() {
        (first, concurrent)
    } else {
        (concurrent, first)
    };
    assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);
    let employee: EnrollResponse = accepted.json().await.unwrap();
    assert!(employee.api_token.starts_with("usr_"));
    assert_eq!(employee.ssh_alias, "t3fleet-alice");
    assert_eq!(employee.server_t3_port, 3773);
    rejected(fleet.enroll(token, "reused"), StatusCode::UNAUTHORIZED).await;

    let second: InviteResponse = ok(fleet
        .admin(Method::POST, "/v1/admin/users/alice/invite")
        .json(&json!({})))
    .await;
    let other_device: EnrollResponse =
        ok(fleet.enroll(&second.enrollment_token, "other-device")).await;
    assert_ne!(employee.api_token, other_device.api_token);
    let status: StatusResponse = ok(fleet.me(&other_device, Method::GET, "/v1/me/status")).await;
    assert_eq!(status.sandbox_id.as_deref(), Some("bx_alice"));
    let revoked: Value = ok(fleet.admin(Method::POST, "/v1/admin/users/alice/revoke")).await;
    assert_eq!(revoked["revoked"], 2);
    for device in [&employee, &other_device] {
        rejected(
            fleet.me(device, Method::GET, "/v1/me/status"),
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    for file in ["fleet.sqlite", "fleet.sqlite-wal"] {
        let bytes = fs::read(fleet.temp.path().join(file)).unwrap();
        for secret in [
            ADMIN,
            token,
            &second.enrollment_token,
            &employee.api_token,
            &other_device.api_token,
        ] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
}

#[tokio::test]
async fn admin_token_is_generated_once_and_can_be_overridden() {
    let fleet = Fleet::start(false).await;
    let database = tempfile::tempdir().unwrap();
    let settings = || {
        let mut settings = settings(&database, &fleet.boat_url, false);
        settings.admin_token = None;
        settings
    };
    let (initial, token) = App::open(settings()).unwrap();
    let token = token.unwrap();
    assert!(token.starts_with("adm_"));
    assert_eq!(token.len(), 68);
    drop(initial);
    let (reopened, generated) = App::open(settings()).unwrap();
    assert!(generated.is_none());
    let (url, task) = serve(reopened.router()).await;
    let path = format!("{url}/v1/admin/users");
    let empty: Vec<StatusResponse> = ok(fleet.http.get(&path).bearer_auth(&token)).await;
    assert!(empty.is_empty());
    task.abort();

    let mut override_settings = settings();
    override_settings.admin_token = Some(ADMIN.into());
    let (overridden, generated) = App::open(override_settings).unwrap();
    assert!(generated.is_none());
    let (url, task) = serve(overridden.router()).await;
    let path = format!("{url}/v1/admin/users");
    rejected(
        fleet.http.get(&path).bearer_auth(token),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let empty: Vec<StatusResponse> = ok(fleet.http.get(&path).bearer_auth(ADMIN)).await;
    assert!(empty.is_empty());
    task.abort();
}

#[tokio::test]
async fn tenants_are_isolated_and_manual_stop_requires_explicit_wake() {
    let fleet = Fleet::start(false).await;
    let alice = fleet.employee("alice", true).await;
    let bob_invite = fleet.invite("bob", false).await;
    assert!(bob_invite.sandbox_id.is_none());
    let bob: EnrollResponse = ok(fleet.enroll(&bob_invite.enrollment_token, "bob-device")).await;
    assert_ne!(alice.sandbox_id, bob.sandbox_id);
    rejected(
        fleet.me(&alice, Method::POST, "/v1/admin/sandboxes/bob/stop"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let stopped: StatusResponse = ok(fleet
        .me(&alice, Method::POST, "/v1/me/stop?username=bob")
        .json(&json!({"sandbox_id": bob.sandbox_id})))
    .await;
    assert_eq!(stopped.sandbox_id.as_deref(), Some("bx_alice"));
    assert_eq!(stopped.state.as_deref(), Some("archived"));
    assert_eq!(stopped.stopped_reason.as_deref(), Some("manual"));
    assert!(stopped.stopped_at.is_some());

    let ticket = |intent| {
        fleet
            .me(&alice, Method::POST, "/v1/me/ssh-ticket?username=bob")
            .json(&json!({"ssh_public_key": KEY, "intent": intent, "sandbox_id": bob.sandbox_id}))
    };
    let reason = rejected(ticket("ssh-proxy"), StatusCode::CONFLICT).await;
    assert!(reason.contains("manually stopped"));
    assert_eq!(
        fleet
            .boat
            .lock()
            .unwrap()
            .count(Method::POST, "/sandboxes/bx_alice/resume"),
        0
    );
    let returned: SshTicketResponse = ok(ticket("explicit")).await;
    assert_eq!(returned.sandbox_id, alice.sandbox_id);
    assert_eq!(returned.port, 22);
    let bob_state: StatusResponse = ok(fleet.me(&bob, Method::GET, "/v1/me/status")).await;
    assert_eq!(bob_state.sandbox_id.as_deref(), Some("bx_bob"));
    assert_ne!(bob_state.state.as_deref(), Some("archived"));

    let _: StatusResponse = ok(fleet.admin(Method::POST, "/v1/admin/sandboxes/bob/stop")).await;
    let wake: StatusResponse = ok(fleet.me(&alice, Method::POST, "/v1/me/wake?username=bob")).await;
    assert_eq!(wake.sandbox_id.as_deref(), Some("bx_alice"));
    assert!(wake.stopped_reason.is_none());
    let bob_state: StatusResponse = ok(fleet.me(&bob, Method::GET, "/v1/me/status")).await;
    assert_eq!(bob_state.state.as_deref(), Some("archived"));
    let _: StatusResponse = ok(fleet.admin(Method::POST, "/v1/admin/sandboxes/bob/wake")).await;
    let _: Value = ok(fleet.admin(Method::DELETE, "/v1/admin/users/bob?delete_sandbox=true")).await;
    rejected(
        fleet.me(&bob, Method::GET, "/v1/me/status"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let boat = fleet.boat.lock().unwrap();
    assert_eq!(boat.count(Method::POST, "/sandboxes/bx_bob/sshkey"), 1);
    assert_eq!(boat.count(Method::POST, "/sandboxes/bx_bob/stop"), 1);
    assert_eq!(boat.count(Method::POST, "/sandboxes/bx_bob/resume"), 1);
    let delete = boat
        .calls
        .iter()
        .find(|call| call.method == Method::DELETE)
        .unwrap();
    assert_eq!(delete.confirm_delete.as_deref(), Some("bx_bob"));
}

#[tokio::test]
async fn provisioning_retry_reuses_the_idempotency_key() {
    let fleet = Fleet::start(false).await;
    fleet.boat.lock().unwrap().fail_create_response = true;
    rejected(
        fleet
            .admin(Method::POST, "/v1/admin/users")
            .json(&json!({"username": "alice", "sandbox_size": "large"})),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    let wake: StatusResponse =
        ok(fleet.admin(Method::POST, "/v1/admin/sandboxes/alice/wake")).await;
    assert_eq!(wake.sandbox_size, "large");
    let boat = fleet.boat.lock().unwrap();
    assert_eq!(boat.machines.len(), 1);
    let creates = boat
        .calls
        .iter()
        .filter(|call| call.path == "/sandboxes")
        .collect::<Vec<_>>();
    assert_eq!(creates.len(), 2);
    assert_eq!(creates[0].idempotency, creates[1].idempotency);
    assert_eq!(creates[0].body, creates[1].body);
}

#[tokio::test]
async fn watchdog_stops_idle_extends_active_ttl_and_survives_probe_failure() {
    let fleet = Fleet::start(false).await;
    let idle = fleet.employee("idle", true).await;
    let active = fleet.employee("active", true).await;
    let failed = fleet.employee("failed", true).await;
    let archived = fleet.employee("archived", true).await;
    {
        let mut boat = fleet.boat.lock().unwrap();
        boat.machines.get_mut("bx_active").unwrap().activity = Activity::Active;
        boat.machines.get_mut("bx_failed").unwrap().activity = Activity::Failed;
        let machine = boat.machines.get_mut("bx_archived").unwrap();
        machine.state = "archived";
        machine.stopped_at = Some(Utc::now().to_rfc3339());
    }
    fleet.app.watch_once().await.unwrap();
    fleet.app.watch_once().await.unwrap();

    for device in [&idle, &archived] {
        let status: StatusResponse = ok(fleet.me(device, Method::GET, "/v1/me/status")).await;
        assert_eq!(status.state.as_deref(), Some("archived"));
        assert_eq!(status.stopped_reason.as_deref(), Some("idle"));
        assert!(status.stopped_at.is_some());
    }
    for device in [&active, &failed] {
        let status: StatusResponse = ok(fleet.me(device, Method::GET, "/v1/me/status")).await;
        assert_ne!(status.state.as_deref(), Some("archived"));
    }
    {
        let boat = fleet.boat.lock().unwrap();
        assert_eq!(boat.count(Method::PATCH, "/sandboxes/bx_active"), 1);
        assert_eq!(boat.count(Method::POST, "/sandboxes/bx_idle/stop"), 1);
        assert_eq!(boat.count(Method::POST, "/sandboxes/bx_failed/stop"), 0);
        assert_eq!(
            boat.count(Method::POST, "/sandboxes/bx_archived/commands"),
            0
        );
    }

    let ticket = |intent| {
        fleet
            .me(&idle, Method::POST, "/v1/me/ssh-ticket")
            .json(&json!({"ssh_public_key": KEY, "intent": intent}))
    };
    let blocked = rejected(ticket("ssh-proxy"), StatusCode::CONFLICT).await;
    assert!(blocked.contains("cooling down"));
    assert_eq!(
        fleet
            .boat
            .lock()
            .unwrap()
            .count(Method::POST, "/sandboxes/bx_idle/resume"),
        0
    );
    let explicit: SshTicketResponse = ok(ticket("explicit")).await;
    assert_eq!(explicit.sandbox_id, idle.sandbox_id);
}

#[tokio::test]
async fn bootstrap_pairing_and_ssh_key_retry() {
    let fleet = Fleet::start(true).await;
    fleet.boat.lock().unwrap().transient_keys = 2;
    let alice = fleet.employee("alice", true).await;
    let _: StatusResponse = ok(fleet.me(&alice, Method::POST, "/v1/me/stop")).await;
    let pair: PairResponse = ok(fleet
        .me(&alice, Method::POST, "/v1/me/pair")
        .json(&json!({"local_port": 13773, "label": "Alice's laptop"})))
    .await;
    assert_eq!(pair.credential, "pair&secret");
    assert_eq!(
        pair.t3_deep_link,
        "t3code://pair?pairingUrl=http%3A%2F%2F127.0.0.1%3A13773%2Fpair%23token%3Dpair%2526secret"
    );
    assert_eq!(pair.ssh_alias, alice.ssh_alias);
    let boat = fleet.boat.lock().unwrap();
    assert_eq!(boat.count(Method::POST, "/sandboxes/bx_alice/sshkey"), 3);
    assert_eq!(boat.count(Method::POST, "/sandboxes/bx_alice/resume"), 1);

    let commands = boat
        .calls
        .iter()
        .filter(|call| call.path == "/sandboxes/bx_alice/commands")
        .map(|call| call.body["command"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(commands.len(), 2);
    assert!(commands[0].contains("curl -fsSL https://t3.codes/install.sh | sh"));
    assert!(commands[0].contains("serve --host 127.0.0.1 --port 3773"));
    assert!(commands[0].contains("Environment=T3CODE_HOME=/home/user/.t3"));
    assert!(commands[1].contains("systemctl start t3code"));
    assert!(commands[1].contains("--base-url 'http://127.0.0.1:13773'"));
    assert!(commands[1].contains(r#"--label 'Alice'"'"'s laptop'"#));
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
async fn cli_join_installs_ssh_config_and_proxy_pins_key_and_relays_bytes() {
    let fleet = Fleet::start(false).await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    fleet.boat.lock().unwrap().endpoint = Some(listener.local_addr().unwrap());

    let cli_invite = |action: &'static str| async {
        let mut cli = fleet.cli();
        cli.args([
            "admin",
            "user",
            action,
            "alice",
            "--server",
            &fleet.server_url,
            "--admin-token",
            ADMIN,
            "--json",
        ]);
        serde_json::from_str::<InviteResponse>(&success(cli.output().await.unwrap())).unwrap()
    };
    let dir = fleet.temp.path().join("device % O'Brien");
    let config = dir.join("config.toml");
    let ssh_config = fleet.temp.path().join("ssh-config");
    let old_config = "# existing SSH config\nHost example\n  User original\n";
    fs::write(&ssh_config, old_config).unwrap();

    let join = |invite: InviteResponse| {
        let mut cli = fleet.cli();
        cli.args([
            "join",
            "--server",
            &fleet.server_url,
            "--token",
            &invite.enrollment_token,
            "--device-name",
            "laptop",
        ])
        .arg("--config-dir")
        .arg(&dir)
        .arg("--ssh-config")
        .arg(&ssh_config);
        cli
    };
    success(join(cli_invite("create").await).output().await.unwrap());
    let identity = fs::read(dir.join("id_ed25519")).unwrap();
    success(join(cli_invite("invite").await).output().await.unwrap());
    assert_eq!(identity, fs::read(dir.join("id_ed25519")).unwrap());
    for path in [&config, &dir.join("id_ed25519")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let fragment = fs::read_to_string(dir.join("ssh/t3fleet-alice.conf")).unwrap();
    assert!(fragment.contains("StrictHostKeyChecking yes"));
    assert!(fragment.contains("ssh-proxy --config"));
    let included = fs::read_to_string(&ssh_config).unwrap();
    assert!(included.starts_with("Include "));
    assert_eq!(included.matches("Include ").count(), 1);
    assert!(included.ends_with(old_config));
    let ssh_options = success(
        Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&ssh_config)
            .arg("t3fleet-alice")
            .env("HOME", fleet.temp.path())
            .output()
            .await
            .unwrap(),
    );
    assert!(ssh_options.contains("hostkeyalias t3fleet-alice"));
    assert!(ssh_options.contains("ssh-proxy --config"));

    let status: StatusResponse = serde_json::from_str(&success(
        fleet
            .cli()
            .arg("--config")
            .arg(&config)
            .args(["status", "--json"])
            .output()
            .await
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(status.username, "alice");
    let links = success(
        fleet
            .cli()
            .arg("--config")
            .arg(&config)
            .args(["connect", "--no-tunnel"])
            .output()
            .await
            .unwrap(),
    );
    assert!(links.contains("t3code://pair") && links.contains("13773"));

    let known_hosts = dir.join("known_hosts");
    let stale = "t3fleet-alice ssh-ed25519 stale\nunrelated ssh-ed25519 key\n";
    fs::write(&known_hosts, stale).unwrap();
    let mut original_known_hosts = fs::File::open(&known_hosts).unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"boat\x00banner").await.unwrap();
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut child = fleet
        .cli()
        .arg("ssh-proxy")
        .arg("--config")
        .arg(&config)
        .args(["--alias", "t3fleet-alice"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    timeout(Duration::from_secs(10), async {
        let mut banner = [0; 11];
        output.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"boat\x00banner");
        input.write_all(b"hi\x00fleet").await.unwrap();
        let mut echoed = [0; 8];
        output.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hi\x00fleet");
        success(child.wait_with_output().await.unwrap());
        echo.await.unwrap();
    })
    .await
    .expect("SSH proxy relays and exits when Boat closes");
    let mut old_contents = String::new();
    original_known_hosts
        .read_to_string(&mut old_contents)
        .unwrap();
    assert_eq!(old_contents, stale);
    let expected_key = KEY.rsplit_once(' ').unwrap().0;
    assert_eq!(
        fs::read_to_string(&known_hosts).unwrap(),
        format!("t3fleet-alice {expected_key}\nunrelated ssh-ed25519 key\n")
    );
    assert_eq!(
        fs::metadata(known_hosts).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn cli_rejects_remote_plain_http_before_writing_local_files() {
    let fleet = Fleet::start(false).await;
    let config_dir = fleet.temp.path().join("unused");
    let output = fleet
        .cli()
        .args([
            "join",
            "--server",
            "http://fleet.example.invalid",
            "--token",
            "enr_test",
        ])
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--ssh-config")
        .arg(fleet.temp.path().join("unused-ssh-config"))
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("plain HTTP enrollment requires"));
    assert!(!config_dir.exists());
    assert!(fleet.boat.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn aggressive_idle_stops_idle_tunnel_and_prevents_reconnect_wake_loop() {
    let fleet = Fleet::start_with_policy(false, WakePolicy::AggressiveIdle).await;
    let idle_tunnel = fleet.employee("tunnel", true).await;
    let active_turn = fleet.employee("busy", true).await;
    {
        let mut boat = fleet.boat.lock().unwrap();
        boat.machines.get_mut("bx_tunnel").unwrap().activity = Activity::IdleTunnelOnly;
        boat.machines.get_mut("bx_busy").unwrap().activity = Activity::Active;
    }

    fleet.app.watch_once().await.unwrap();

    let tunnel_status: StatusResponse =
        ok(fleet.me(&idle_tunnel, Method::GET, "/v1/me/status")).await;
    assert_eq!(tunnel_status.state.as_deref(), Some("archived"));
    assert_eq!(tunnel_status.stopped_reason.as_deref(), Some("idle"));
    assert_eq!(tunnel_status.wake_policy, WakePolicy::AggressiveIdle);
    assert_eq!(
        tunnel_status.activity.as_ref().map(|a| a.t3_http_conns),
        Some(1)
    );

    let busy_status: StatusResponse =
        ok(fleet.me(&active_turn, Method::GET, "/v1/me/status")).await;
    assert_ne!(busy_status.state.as_deref(), Some("archived"));
    assert_eq!(
        busy_status.activity.as_ref().map(|a| a.active_turns),
        Some(1)
    );

    // Passive ssh-proxy must NOT wake under aggressive-idle (avoids T3 reconnect loops)
    let err = rejected(
        fleet
            .me(&idle_tunnel, Method::POST, "/v1/me/ssh-ticket")
            .json(&json!({"ssh_public_key": KEY, "intent": "ssh-proxy"})),
        StatusCode::CONFLICT,
    )
    .await;
    assert!(err.contains("aggressive-idle"));
    assert_eq!(
        fleet
            .boat
            .lock()
            .unwrap()
            .count(Method::POST, "/sandboxes/bx_tunnel/resume"),
        0
    );

    // Explicit wake succeeds immediately
    let explicit: SshTicketResponse = ok(fleet
        .me(&idle_tunnel, Method::POST, "/v1/me/ssh-ticket")
        .json(&json!({"ssh_public_key": KEY, "intent": "explicit"})))
    .await;
    assert_eq!(explicit.sandbox_id, idle_tunnel.sandbox_id);
}
