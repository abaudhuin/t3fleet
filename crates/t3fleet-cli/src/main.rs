mod api;
mod config;

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitCode, ExitStatus},
    task::{Context as TaskContext, Poll, ready},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use anyhow::{Context, Result, ensure};
use api::{Api, send};
use clap::{Args, Parser, Subcommand, ValueEnum};
use config::Config;
use reqwest::{Method, RequestBuilder};
use serde::Serialize;
use serde_json::Value;
use t3fleet_protocol::*;
use tokio::{
    io::{self, AsyncWrite},
    net::TcpStream,
    process::Command,
    sync::oneshot,
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
        #[arg(long)]
        sandbox: Option<String>,
        #[arg(long)]
        usage: bool,
    },
    Wake {
        #[arg(long)]
        sandbox: Option<String>,
    },
    Stop {
        #[arg(long)]
        sandbox: Option<String>,
    },
    Ssh {
        #[arg(long)]
        sandbox: Option<String>,
        #[arg(last = true)]
        command: Vec<String>,
    },
    Sandbox {
        #[command(subcommand)]
        action: EmployeeSandboxAction,
    },
    Sync,
    #[command(hide = true)]
    SshProxy {
        #[arg(long)]
        alias: String,
    },
    Admin(Admin),
}

#[derive(Subcommand)]
enum EmployeeSandboxAction {
    List {
        #[arg(long)]
        json: bool,
    },
    New {
        name: String,
        #[arg(long, value_enum)]
        size: Option<Size>,
        #[arg(long)]
        template: Option<String>,
    },
    Rm {
        name: String,
    },
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
    Usage {
        #[arg(long)]
        json: bool,
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
        template: Option<String>,
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
    Wake {
        username: String,
        #[arg(long)]
        sandbox: Option<String>,
    },
    Stop {
        username: String,
        #[arg(long)]
        sandbox: Option<String>,
    },
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
        let path = config::absolute(path)?;
        let config = Config::read(&path)?;
        match action {
            Action::Ssh { sandbox, command } => {
                let status = ssh(&config)
                    .arg(config.alias(sandbox.as_deref())?)
                    .args(command)
                    .status()
                    .await
                    .context("running ssh")?;
                return Ok(exit_code(status));
            }
            Action::SshProxy { alias } => proxy(&config, &alias).await?,
            Action::Status {
                json,
                sandbox,
                usage,
            } => {
                let status = send(
                    sandbox_request(&config, Method::GET, "status", sandbox.as_deref())?
                        .query(&[("include_usage", usage)]),
                )
                .await?;
                print_status(&status, json)?;
            }
            Action::Wake { sandbox } => change_state(&config, "wake", sandbox.as_deref()).await?,
            Action::Stop { sandbox } => change_state(&config, "stop", sandbox.as_deref()).await?,
            Action::Sandbox { action } => employee_sandbox(&config, &path, action).await?,
            Action::Sync => {
                let count = sync_ssh(&config, &path).await?;
                println!("Synced {count} SSH host(s)");
            }
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
    config::validate_ssh_user(&response.ssh_user)?;
    let config = Config {
        server: args.server,
        username: response.username,
        api_token: response.api_token,
        ssh_alias: response.ssh_alias,
        ssh_user: response.ssh_user,
        sandbox_id: response.sandbox_id,
        ssh_config,
        identity_file,
        known_hosts,
    };
    config.write(&config_path)?;
    config::write_ssh(&config, &config_path, &config.ssh_alias, &config.ssh_user)?;
    config::include_ssh(&config)?;
    if let Err(error) = sync_ssh(&config, &config_path).await {
        eprintln!("Could not sync all SSH hosts: {error:#}. Run 't3fleet sync' to retry.");
    }
    println!(
        "Joined as {}. SSH host {}",
        config.username, config.ssh_alias
    );
    println!("{}", t3_setup_steps(&config.ssh_alias));
    Ok(())
}

fn t3_setup_steps(alias: &str) -> String {
    format!(
        "\nFinish in T3 Code Desktop (one time):\n  \
         1. On the Welcome screen, click Start without an agent\n  \
         2. Open Settings > Environments > Add environment > SSH\n  \
         3. Select {alias}, then click Add environment\n  \
         4. In a new thread, choose your sandbox under Run on\n\n\
         T3 Code then reconnects and wakes your sandbox by itself. No terminal has to stay open."
    )
}

fn employee_request(config: &Config, method: Method, segments: &[&str]) -> Result<RequestBuilder> {
    let api = Api::new(&config.server, true)?;
    Ok(api.request(method, segments).bearer_auth(&config.api_token))
}

fn with_sandbox(request: RequestBuilder, sandbox: Option<&str>) -> RequestBuilder {
    match sandbox {
        Some(name) => request.query(&[("sandbox", name)]),
        None => request,
    }
}

fn sandbox_request(
    config: &Config,
    method: Method,
    action: &str,
    sandbox: Option<&str>,
) -> Result<RequestBuilder> {
    Ok(with_sandbox(
        employee_request(config, method, &["v1", "me", action])?,
        sandbox,
    ))
}

async fn change_state(config: &Config, action: &str, sandbox: Option<&str>) -> Result<()> {
    let status = send(sandbox_request(config, Method::POST, action, sandbox)?).await?;
    print_status(&status, false)
}

async fn list_sandboxes(config: &Config) -> Result<Vec<StatusResponse>> {
    send(employee_request(
        config,
        Method::GET,
        &["v1", "me", "sandboxes"],
    )?)
    .await
}

fn status_alias(config: &Config, status: &StatusResponse) -> Result<String> {
    let alias = config.alias(status.sandbox_name.as_deref())?;
    ensure!(
        status.ssh_alias.as_deref() == Some(&alias),
        "unexpected SSH alias from fleet server"
    );
    Ok(alias)
}

async fn sync_ssh(config: &Config, config_path: &Path) -> Result<usize> {
    let statuses = list_sandboxes(config).await?;
    let aliases = statuses
        .iter()
        .map(|status| status_alias(config, status))
        .collect::<Result<Vec<_>>>()?;
    for (alias, status) in aliases.iter().zip(&statuses) {
        config::write_ssh(config, config_path, alias, &status.ssh_user)?;
    }
    config::include_ssh(config)?;
    config::prune_ssh(config, &aliases)?;
    Ok(aliases.len())
}

async fn employee_sandbox(
    config: &Config,
    config_path: &Path,
    action: EmployeeSandboxAction,
) -> Result<()> {
    match action {
        EmployeeSandboxAction::List { json: machine } => {
            let statuses = list_sandboxes(config).await?;
            if machine {
                return json(&statuses);
            }
            for status in statuses {
                print_status(&status, false)?;
            }
        }
        EmployeeSandboxAction::New {
            name,
            size,
            template,
        } => {
            let status: StatusResponse = send(
                employee_request(config, Method::POST, &["v1", "me", "sandboxes"])?.json(
                    &CreateSandboxRequest {
                        name,
                        size: size.map(Into::into),
                        template,
                    },
                ),
            )
            .await?;
            let alias = status_alias(config, &status)?;
            config::write_ssh(config, config_path, &alias, &status.ssh_user)?;
            println!("SSH host {alias}");
        }
        EmployeeSandboxAction::Rm { name } => {
            let alias = config.alias(Some(&name))?;
            let _: Value = send(employee_request(
                config,
                Method::DELETE,
                &["v1", "me", "sandboxes", &name],
            )?)
            .await?;
            config::remove_ssh(config, &alias)?;
            println!("Deleted sandbox {name}");
        }
    }
    Ok(())
}

fn json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_status(status: &StatusResponse, machine: bool) -> Result<()> {
    if machine {
        return json(status);
    }
    print!("{}", status.username);
    if let Some(name) = status
        .sandbox_name
        .as_deref()
        .filter(|name| *name != DEFAULT_SANDBOX_NAME)
    {
        print!("/{name}");
    }
    print!("  {}", status.state.as_deref().unwrap_or("not provisioned"));
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
    if let Some(usage) = &status.usage {
        print!("  {}", format_usage(usage));
    }
    println!();
    Ok(())
}

fn format_usage(usage: &SandboxUsage) -> String {
    format!(
        "{:.2} billable hours  ${:.4}",
        usage.seconds as f64 / 3600.0,
        usage.dollars
    )
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
                template,
                no_provision,
                invite_ttl_secs,
                json,
            } => {
                let response = send(request(Method::POST, &["v1", "admin", "users"]).json(
                    &CreateUserRequest {
                        username,
                        sandbox_size: size.into(),
                        template,
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
            let (username, sandbox, action) = match action {
                SandboxAction::Wake { username, sandbox } => (username, sandbox, "wake"),
                SandboxAction::Stop { username, sandbox } => (username, sandbox, "stop"),
            };
            let status = send(with_sandbox(
                request(
                    Method::POST,
                    &["v1", "admin", "sandboxes", &username, action],
                ),
                sandbox.as_deref(),
            ))
            .await?;
            print_status(&status, false)?;
        }
        AdminResource::Usage { json: machine } => {
            let entries: Vec<AdminUsageEntry> =
                send(request(Method::GET, &["v1", "admin", "usage"])).await?;
            if machine {
                return json(&entries);
            }
            for entry in entries {
                println!(
                    "{}/{}  {}  {}  {}",
                    entry.username,
                    entry.sandbox_name,
                    entry.state,
                    entry.sandbox_id,
                    format_usage(&entry.usage)
                );
            }
        }
    }
    Ok(())
}

fn ssh(config: &Config) -> Command {
    let mut command = Command::new(config::SSH_PROGRAM);
    command
        .arg("-F")
        .arg(&config.ssh_config)
        .env("T3FLEET_WAKE_INTENT", "explicit");
    command
}

fn exit_code(status: ExitStatus) -> u8 {
    let code = status.code();
    #[cfg(unix)]
    let code = code.or_else(|| status.signal().map(|signal| 128 + signal));
    code.unwrap_or(1) as u8
}

async fn proxy(config: &Config, alias: &str) -> Result<()> {
    let sandbox_name = config.sandbox_name(alias)?.map(str::to_owned);
    let intent = if std::env::var("T3FLEET_WAKE_INTENT").as_deref() == Ok("explicit") {
        WakeIntent::Explicit
    } else {
        WakeIntent::SshProxy
    };
    let ticket: SshTicketResponse = send(
        employee_request(config, Method::POST, &["v1", "me", "ssh-ticket"])?.json(
            &SshTicketRequest {
                ssh_public_key: config.public_key()?,
                intent,
                sandbox_name,
            },
        ),
    )
    .await?;
    config::validate_ssh_user(&ticket.ssh_user)?;
    ensure!(
        ticket.port != 0 && valid_ssh_host(&ticket.host),
        "invalid SSH endpoint"
    );
    if let Some(host_key) = &ticket.host_key {
        config::pin_host(&config.known_hosts_for(alias)?, alias, host_key)?;
    }
    let socket = tokio::time::timeout(
        Duration::from_secs(20),
        TcpStream::connect((ticket.host.as_str(), ticket.port)),
    )
    .await
    .context("timed out connecting to SSH endpoint")?
    .context("connecting to SSH endpoint")?;
    relay(socket).await
}

fn valid_ssh_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || (host.len() <= 253
            && host
                .strip_suffix('.')
                .unwrap_or(host)
                .split('.')
                .all(|label| {
                    (1..=63).contains(&label.len())
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }))
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
