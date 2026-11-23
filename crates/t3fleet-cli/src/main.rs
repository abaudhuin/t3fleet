mod api;
mod config;

use std::{
    net::Ipv4Addr,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitCode, ExitStatus, Stdio},
    task::{Context as TaskContext, Poll, ready},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use api::{Api, send};
use clap::{Args, Parser, Subcommand, ValueEnum};
use config::Config;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;
use t3fleet_protocol::*;
use tokio::{
    io::{self, AsyncWrite},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::oneshot,
    time::{Instant, sleep},
};

#[derive(Parser)]
#[command(version, about = "Manage and connect to your T3 Code sandbox")]
struct Cli {
    #[arg(long, global = true, env = "T3FLEET_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Join(Join),
    Status {
        #[arg(long)]
        json: bool,
    },
    Wake,
    Stop,
    Ssh {
        #[arg(last = true)]
        command: Vec<String>,
    },
    Connect {
        #[arg(long, default_value_t = 13773, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        #[arg(long)]
        no_tunnel: bool,
    },
    #[command(hide = true)]
    SshProxy {
        #[arg(long)]
        alias: String,
    },
    Admin(Admin),
}

#[derive(Args)]
struct Join {
    #[arg(long)]
    server: String,
    #[arg(long, hide_env_values = true)]
    token: String,
    #[arg(long)]
    config_dir: Option<PathBuf>,
    #[arg(long, env = "T3FLEET_SSH_CONFIG")]
    ssh_config: Option<PathBuf>,
    #[arg(long)]
    device_name: Option<String>,
    #[arg(long)]
    allow_insecure_http: bool,
}

#[derive(Args)]
struct Admin {
    #[arg(long, global = true, env = "T3FLEET_SERVER")]
    server: Option<String>,
    #[arg(
        long,
        global = true,
        env = "T3FLEET_ADMIN_TOKEN",
        hide_env_values = true
    )]
    admin_token: Option<String>,
    #[arg(long, global = true)]
    allow_insecure_http: bool,
    #[command(subcommand)]
    resource: AdminResource,
}

#[derive(Subcommand)]
enum AdminResource {
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Size {
    Small,
    Default,
    Large,
}

impl From<Size> for SandboxSize {
    fn from(size: Size) -> Self {
        match size {
            Size::Small => Self::Small,
            Size::Default => Self::Default,
            Size::Large => Self::Large,
        }
    }
}

#[derive(Subcommand)]
enum UserAction {
    Create {
        username: String,
        #[arg(long, value_enum, default_value = "small")]
        size: Size,
        #[arg(long)]
        no_provision: bool,
        #[arg(long, default_value_t = default_invite_ttl())]
        invite_ttl_secs: u64,
        #[arg(long)]
        json: bool,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Invite {
        username: String,
        #[arg(long, default_value_t = default_invite_ttl())]
        invite_ttl_secs: u64,
        #[arg(long)]
        json: bool,
    },
    Revoke {
        username: String,
    },
    Delete {
        username: String,
        #[arg(long)]
        delete_sandbox: bool,
    },
}

#[derive(Subcommand)]
enum SandboxAction {
    Wake { username: String },
    Stop { username: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| {
            let result = runtime.block_on(cli.run());
            // Tokio's stdin reader can still be blocked after the remote socket closes.
            runtime.shutdown_background();
            result
        });
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("t3fleet: {error:#}");
            ExitCode::FAILURE
        }
    }
}

impl Cli {
    async fn run(self) -> Result<u8> {
        let action = match self.command {
            Action::Join(args) => {
                join(args, self.config).await?;
                return Ok(0);
            }
            Action::Admin(args) => {
                admin(args).await?;
                return Ok(0);
            }
            action => action,
        };
        let path = match self.config {
            Some(path) => path,
            None => config::default_dir()?.join("config.toml"),
        };
        let config = Config::read(&path)?;
        match action {
            Action::Ssh { command } => {
                let status = ssh(&config)
                    .arg(&config.ssh_alias)
                    .args(command)
                    .status()
                    .await
                    .context("running ssh")?;
                return Ok(exit_code(status));
            }
            Action::SshProxy { alias } => proxy(&config, &alias).await?,
            Action::Connect { port, no_tunnel } => connect(&config, port, no_tunnel).await?,
            Action::Status { json } => {
                let status = employee(&config, Method::GET, "status").await?;
                print_status(&status, json)?;
            }
            Action::Wake => print_status(&employee(&config, Method::POST, "wake").await?, false)?,
            Action::Stop => print_status(&employee(&config, Method::POST, "stop").await?, false)?,
            Action::Join(_) | Action::Admin(_) => unreachable!(),
        }
        Ok(0)
    }
}

async fn join(args: Join, config_path: Option<PathBuf>) -> Result<()> {
    let api = Api::new(&args.server, args.allow_insecure_http)?;
    let dir = config::absolute(match (args.config_dir, config_path.as_deref()) {
        (Some(dir), _) => dir,
        (None, Some(path)) => path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned(),
        (None, None) => config::default_dir()?,
    })?;
    let config_path = config::absolute(config_path.unwrap_or_else(|| dir.join("config.toml")))?;
    let ssh_config = config::absolute(match args.ssh_config {
        Some(path) => path,
        None => config::default_ssh_config()?,
    })?;
    let identity_file = dir.join("id_ed25519");
    let known_hosts = dir.join("known_hosts");
    let fragment_dir = dir.join("ssh");
    let identity_public = identity_file.with_extension("pub");
    for path in [&config_path, &ssh_config] {
        ensure!(
            ![&identity_file, &identity_public, &known_hosts].contains(&path)
                && !path.starts_with(&fragment_dir)
                && config_path != ssh_config,
            "SSH configuration and fleet configuration must use separate paths"
        );
    }
    config::create_dir(&dir)?;
    config::create_dir(config_path.parent().context("config path has no parent")?)?;
    let ssh_public_key = config::ensure_key(&identity_file).await?;
    let device_name = args
        .device_name
        .or_else(|| std::env::var("HOSTNAME").ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "t3fleet-cli".into());
    let response: EnrollResponse = send(api.request(Method::POST, &["v1", "enroll"]).json(
        &EnrollRequest {
            token: args.token,
            ssh_public_key,
            device_name,
        },
    ))
    .await?;
    config::validate_alias(&response.ssh_alias)?;
    ensure!(
        response.server_t3_port != 0,
        "server returned an invalid T3 Code port"
    );
    let config = Config {
        server: args.server,
        username: response.username,
        api_token: response.api_token,
        ssh_alias: response.ssh_alias,
        sandbox_id: response.sandbox_id,
        server_t3_port: response.server_t3_port,
        ssh_config,
        identity_file,
        known_hosts,
    };
    config.write(&config_path)?;
    config::write_ssh(&config, &config_path, &dir)?;
    println!(
        "Joined as {}. SSH host {}",
        config.username, config.ssh_alias
    );
    Ok(())
}

async fn employee(config: &Config, method: Method, action: &str) -> Result<StatusResponse> {
    let api = Api::new(&config.server, true)?;
    send(
        api.request(method, &["v1", "me", action])
            .bearer_auth(&config.api_token),
    )
    .await
}

fn json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_status(status: &StatusResponse, machine: bool) -> Result<()> {
    if machine {
        return json(status);
    }
    print!(
        "{}  {}",
        status.username,
        status.state.as_deref().unwrap_or("not provisioned")
    );
    if let Some(id) = &status.sandbox_id {
        print!("  {id}");
    }
    if let Some(reason) = &status.stopped_reason {
        print!("  ({reason})");
    }
    print!("  [policy:{}]", status.wake_policy.as_str());
    if let Some(activity) = &status.activity {
        print!(
            "  turns={} ptys={} ssh={} t3={}",
            activity.active_turns,
            activity.interactive_ptys,
            activity.ssh_conns,
            activity.t3_http_conns
        );
    }
    println!();
    Ok(())
}

fn print_invite(invite: &InviteResponse, machine: bool) -> Result<()> {
    if machine {
        return json(invite);
    }
    println!(
        "Enrollment token for {}\n{}\nExpires {}",
        invite.username, invite.enrollment_token, invite.expires_at
    );
    Ok(())
}

async fn admin(args: Admin) -> Result<()> {
    let server = args
        .server
        .as_deref()
        .context("--server or T3FLEET_SERVER is required")?;
    let token = args
        .admin_token
        .as_deref()
        .context("--admin-token or T3FLEET_ADMIN_TOKEN is required")?;
    let api = Api::new(server, args.allow_insecure_http)?;
    let request = |method, segments: &[&str]| api.request(method, segments).bearer_auth(token);
    match args.resource {
        AdminResource::User { action } => match action {
            UserAction::Create {
                username,
                size,
                no_provision,
                invite_ttl_secs,
                json,
            } => {
                let response = send(request(Method::POST, &["v1", "admin", "users"]).json(
                    &CreateUserRequest {
                        username,
                        sandbox_size: size.into(),
                        provision_now: !no_provision,
                        invite_ttl_secs,
                    },
                ))
                .await?;
                print_invite(&response, json)?;
            }
            UserAction::List { json: machine } => {
                let users: Vec<StatusResponse> =
                    send(request(Method::GET, &["v1", "admin", "users"])).await?;
                if machine {
                    json(&users)?;
                } else {
                    for user in users {
                        print_status(&user, false)?;
                    }
                }
            }
            UserAction::Invite {
                username,
                invite_ttl_secs,
                json,
            } => {
                let response = send(
                    request(Method::POST, &["v1", "admin", "users", &username, "invite"])
                        .json(&InviteRequest { invite_ttl_secs }),
                )
                .await?;
                print_invite(&response, json)?;
            }
            UserAction::Revoke { username } => {
                let response: Value = send(request(
                    Method::POST,
                    &["v1", "admin", "users", &username, "revoke"],
                ))
                .await?;
                println!(
                    "Revoked {} device token(s) for {username}",
                    response["revoked"]
                );
            }
            UserAction::Delete {
                username,
                delete_sandbox,
            } => {
                let _: Value = send(
                    request(Method::DELETE, &["v1", "admin", "users", &username])
                        .query(&[("delete_sandbox", delete_sandbox)]),
                )
                .await?;
                println!("Deleted {username}");
            }
        },
        AdminResource::Sandbox { action } => {
            let (username, action) = match action {
                SandboxAction::Wake { username } => (username, "wake"),
                SandboxAction::Stop { username } => (username, "stop"),
            };
            let status = send(request(
                Method::POST,
                &["v1", "admin", "sandboxes", &username, action],
            ))
            .await?;
            print_status(&status, false)?;
        }
    }
    Ok(())
}

fn ssh(config: &Config) -> Command {
    let mut command = Command::new("ssh");
    command
        .arg("-F")
        .arg(&config.ssh_config)
        .env("T3FLEET_WAKE_INTENT", "explicit");
    command
}

fn exit_code(status: ExitStatus) -> u8 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1) as u8
}

async fn proxy(config: &Config, alias: &str) -> Result<()> {
    ensure!(
        alias == config.ssh_alias,
        "SSH alias does not match fleet configuration"
    );
    config::validate_alias(alias)?;
    let intent = if std::env::var("T3FLEET_WAKE_INTENT").as_deref() == Ok("explicit") {
        WakeIntent::Explicit
    } else {
        WakeIntent::SshProxy
    };
    let api = Api::new(&config.server, true)?;
    let ticket: SshTicketResponse = send(
        api.request(Method::POST, &["v1", "me", "ssh-ticket"])
            .bearer_auth(&config.api_token)
            .json(&SshTicketRequest {
                ssh_public_key: config.public_key()?,
                intent,
            }),
    )
    .await?;
    ensure!(ticket.ssh_user == "user", "unexpected Boat SSH user");
    ensure!(
        ticket.sandbox_id == config.sandbox_id,
        "ticket sandbox does not match fleet configuration"
    );
    config::pin_host(&config.known_hosts, alias, &ticket.host_key)?;
    let socket = tokio::time::timeout(
        Duration::from_secs(20),
        TcpStream::connect((ticket.host.as_str(), ticket.port)),
    )
    .await
    .context("timed out connecting to Boat SSH endpoint")?
    .context("connecting to Boat SSH endpoint")?;
    relay(socket).await
}

async fn relay(mut socket: TcpStream) -> Result<()> {
    let (closed, remote_eof) = oneshot::channel();
    let stdout = ProxyOutput {
        stdout: io::stdout(),
        closed: Some(closed),
    };
    let mut stdio = io::join(io::stdin(), stdout);
    tokio::select! {
        result = io::copy_bidirectional(&mut stdio, &mut socket) => { result?; }
        _ = remote_eof => {}
    }
    Ok(())
}

struct ProxyOutput {
    stdout: io::Stdout,
    closed: Option<oneshot::Sender<()>>,
}

impl AsyncWrite for ProxyOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(Pin::new(&mut self.stdout).poll_shutdown(cx))?;
        // Remote EOF needs to close the proxy even while OpenSSH is holding stdin open.
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
        Poll::Ready(Ok(()))
    }
}

async fn connect(config: &Config, port: u16, no_tunnel: bool) -> Result<()> {
    let local = (Ipv4Addr::LOCALHOST, port);
    if !no_tunnel {
        TcpListener::bind(local)
            .await
            .with_context(|| format!("local port {port} is unavailable"))?;
    }
    let api = Api::new(&config.server, true)?;
    let response: PairResponse = send(
        api.request(Method::POST, &["v1", "me", "pair"])
            .bearer_auth(&config.api_token)
            .json(&PairRequest {
                local_port: port,
                label: format!("t3fleet {}", config.username),
            }),
    )
    .await?;
    ensure!(
        response.ssh_alias == config.ssh_alias && response.local_port == port,
        "pairing response does not match the requested tunnel"
    );

    if no_tunnel {
        println!(
            "Pair in T3 Code using this URL\n{}\nOpen in T3 Code Desktop\n{}",
            response.pair_url, response.t3_deep_link
        );
        println!("An SSH tunnel to 127.0.0.1:{port} is required to use these links.");
        return Ok(());
    }

    let forward = format!("127.0.0.1:{port}:127.0.0.1:{}", config.server_t3_port);
    let mut child = ssh(config)
        .args([
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            &forward,
            &config.ssh_alias,
        ])
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("starting SSH tunnel")?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    let shutdown = async {
        tokio::select! {
            res = tokio::signal::ctrl_c() => res,
            _ = sigterm.recv() => Ok(()),
        }
    };
    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut shutdown => { result?; child.kill().await?; return Ok(()); }
        result = wait_for_tunnel(&mut child, port) => result?,
    }

    println!(
        "Pair in T3 Code using this URL\n{}\nOpen in T3 Code Desktop\n{}",
        response.pair_url, response.t3_deep_link
    );
    println!("Keep this terminal open while connected. Press Ctrl+C to close the tunnel.");
    tokio::select! {
        result = &mut shutdown => { result?; child.kill().await?; }
        status = child.wait() => {
            let status = status?;
            ensure!(status.success(), "SSH tunnel exited with {status}");
        }
    }
    Ok(())
}

async fn wait_for_tunnel(child: &mut Child, port: u16) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("SSH tunnel exited before opening port {port} ({status})");
        }
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "SSH tunnel did not open port {port} within 60 seconds"
        );
        sleep(Duration::from_millis(100)).await;
    }
}
