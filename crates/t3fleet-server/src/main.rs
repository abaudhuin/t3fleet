use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use t3fleet_protocol::WakePolicy;
use t3fleet_server::{App, Settings};
use tokio::{net::TcpListener, time::MissedTickBehavior};

#[derive(Clone, Copy, ValueEnum)]
enum PolicyArg {
    Auto,
    AggressiveIdle,
    Explicit,
}

impl From<PolicyArg> for WakePolicy {
    fn from(value: PolicyArg) -> Self {
        match value {
            PolicyArg::Auto => Self::Auto,
            PolicyArg::AggressiveIdle => Self::AggressiveIdle,
            PolicyArg::Explicit => Self::Explicit,
        }
    }
}

#[derive(Parser)]
#[command(version, about = "Control plane for T3 Code sandboxes")]
struct Args {
    #[arg(long, env = "T3FLEET_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long, env = "T3FLEET_DB", default_value = "./t3fleet.db")]
    db: PathBuf,
    #[arg(long, env = "BOAT_API_KEY", hide_env_values = true)]
    boat_api_key: String,
    #[arg(long, env = "BOAT_ORG")]
    boat_org: Option<String>,
    #[arg(long, env = "BOAT_API_BASE", default_value = "https://boat.dev/api/v1")]
    boat_api_base: String,
    #[arg(long, env = "T3FLEET_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
    #[arg(long, env = "T3FLEET_IDLE_TIMEOUT_SECS", default_value_t = 900)]
    idle_timeout_secs: u64,
    #[arg(long, env = "T3FLEET_SAFETY_TTL_SECS", default_value_t = 7200)]
    safety_ttl_secs: u64,
    #[arg(long, env = "T3FLEET_WATCH_INTERVAL_SECS", default_value_t = 60)]
    watch_interval_secs: u64,
    #[arg(long, env = "T3FLEET_AUTO_WAKE_COOLDOWN_SECS", default_value_t = 120)]
    auto_wake_cooldown_secs: u64,
    #[arg(long, value_enum, env = "T3FLEET_WAKE_POLICY", default_value = "auto")]
    wake_policy: PolicyArg,
    #[arg(long, env = "T3FLEET_SKIP_BOOTSTRAP")]
    skip_bootstrap: bool,
    #[arg(long, env = "T3FLEET_MAX_SANDBOXES_PER_USER", default_value_t = 5)]
    max_sandboxes_per_user: usize,
    #[arg(long, env = "T3FLEET_DEFAULT_TEMPLATE")]
    default_template: Option<String>,
    #[arg(long, env = "T3FLEET_SNAPSHOT_RETENTION_DAYS", default_value_t = 13)]
    snapshot_retention_days: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let listener = TcpListener::bind(args.listen).await?;
    let (app, generated_token) = App::open(Settings {
        db: args.db,
        boat_api_key: args.boat_api_key,
        boat_org: args.boat_org,
        boat_api_base: args.boat_api_base,
        admin_token: args.admin_token,
        idle_timeout: Duration::from_secs(args.idle_timeout_secs),
        safety_ttl: args.safety_ttl_secs,
        cooldown: Duration::from_secs(args.auto_wake_cooldown_secs),
        wake_policy: args.wake_policy.into(),
        skip_bootstrap: args.skip_bootstrap,
        max_sandboxes_per_user: args.max_sandboxes_per_user,
        default_template: args.default_template,
        snapshot_retention_days: args.snapshot_retention_days,
    })?;
    if let Some(token) = generated_token {
        eprintln!("Initial t3fleet admin token: {token}");
    }
    if args.watch_interval_secs > 0 {
        let app = app.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(args.watch_interval_secs));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = app.watch_once().await {
                    tracing::error!(%error, "watchdog cycle failed");
                }
            }
        });
    }
    tracing::info!(address = %listener.local_addr()?, "t3fleet listening");
    axum::serve(listener, app.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
