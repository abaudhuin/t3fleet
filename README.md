# t3fleet

A small Rust control plane and CLI for running per-user [boat.dev](https://boat.dev) cloud sandboxes with stock [T3 Code](https://t3.codes) — no T3 Code fork, no public HTTP ports, and automatic idle stop/resume.

It is an early, intentionally bare-bones tool aimed at small engineering teams (roughly 5–20 people) who want centralized sandbox provisioning and cost control while keeping all agent orchestration, threads, and worktrees inside T3 Code itself.

## How it works

```text
  Employee laptop                          Control plane (VPS / NAS)                boat.dev
  ┌──────────────────────────┐             ┌──────────────────────────┐             ┌──────────────────────────────┐
  │ T3 Code Desktop          │             │ t3fleet-server (Rust)    │   HTTPS     │ Isolated Ubuntu VM (noEnv)   │
  │   └─ OpenSSH             │  HTTPS /    │   ├─ SQLite state        │────────────▶│   ├─ sshd (per-user pubkey)  │
  │        └─ ProxyCommand   │  Tailscale  │   ├─ Enrollment & RBAC   │  Boat API   │   └─ t3code.service          │
  │             t3fleet      │────────────▶│   ├─ Idle watchdog       │   (server   │        127.0.0.1:3773 ONLY   │
  │               │          │             │   └─ 14d snapshot guard  │    only)    │                              │
  │               └──────────┼─────────────┴──────────────────────────┴────────────▶│  End-to-end SSH (direct TCP) │
  └──────────────────────────┘       host key pinned from Boat API on connect       └──────────────────────────────┘
```

- **Server (`t3fleet-server`):** Axum + bundled SQLite. Talks to sandboxes through a pluggable `SandboxProvider` trait (currently implementing `boat.dev`; see [docs/providers.md](docs/providers.md)). Holds `BOAT_API_KEY`, provisions `noEnv: true` Boat sandboxes, manages single-use onboarding invites and revocable per-device tokens, runs the idle-stop watchdog, and preserves stopped disks before Boat's 14-day retention window.
- **CLI (`t3fleet`):** Used by both admins and employees. Enrolls a device, manages OpenSSH config fragments, acts as the OpenSSH `ProxyCommand` (waking the sandbox and pinning its fresh Boat host key before relaying raw TCP), and can open a local loopback tunnel + one-time T3 pairing link.
- **T3 Code stays untouched:** Inside each sandbox, `t3 serve --host 127.0.0.1 --port 3773` runs under `systemd` as `user`. Nothing is exposed on a public HTTP port.

## Install

### Client CLI (macOS, Linux, Windows)

**macOS & Linux:**
```sh
curl -fsSL https://raw.githubusercontent.com/abaudhuin/t3fleet/main/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/abaudhuin/t3fleet/main/install.ps1 | iex
```

**Server + CLI (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/abaudhuin/t3fleet/main/install.sh | sh -s -- --server
```

**From source (Rust):**
```sh
cargo install --path crates/t3fleet-cli
cargo install --path crates/t3fleet-server
```

Prebuilt release archives (`x86_64` / `aarch64` Linux & macOS, `x86_64` Windows) and `SHA256SUMS.txt` are published on [GitHub Releases](https://github.com/abaudhuin/t3fleet/releases).

## Quickstart

### 1. Run the control plane

Set `BOAT_API_KEY` (and `BOAT_ORG` if needed) on a small always-on host (a VPS or NAS on Tailscale, or behind Caddy/HTTPS):

```sh
BOAT_API_KEY=boat_... t3fleet-server --listen 127.0.0.1:8080 --db ./t3fleet.db
```

On first boot without `T3FLEET_ADMIN_TOKEN`, the server generates an `adm_...` admin token, stores only its SHA-256 hash in SQLite, and prints it once to stderr.

Deployment examples live in [Dockerfile](Dockerfile), [deploy/t3fleet-server.service](deploy/t3fleet-server.service), and [deploy/Caddyfile.example](deploy/Caddyfile.example).

### 2. Onboard an employee

```sh
export T3FLEET_SERVER=https://fleet.example.com   # or http://100.x.y.z:8080 over Tailscale
export T3FLEET_ADMIN_TOKEN=adm_...

t3fleet admin user create alice --size small
```

Send the printed single-use `enr_...` enrollment token to the employee. On their machine:

```sh
t3fleet join --server https://fleet.example.com --token enr_...
```

`join` generates a dedicated Ed25519 keypair (`0600`), registers it with the control plane, writes `~/.config/t3fleet/ssh/t3fleet-alice.conf`, and adds an `Include` line at the top of `~/.ssh/config`.

### 3. Connect T3 Code

- **T3 Code Desktop (native SSH):** Open **Settings → Environments → Add environment → SSH** and pick `t3fleet-alice`. T3 Desktop reuses the running `t3code.service` on `127.0.0.1:3773` over the SSH connection.
- **One-command tunnel + pairing link:**
  ```sh
  t3fleet connect
  ```
  Opens a loopback SSH tunnel (`127.0.0.1:13773` → sandbox `127.0.0.1:3773`), mints a 15-minute one-time pairing token inside the sandbox, and prints both the browser URL (`http://127.0.0.1:13773/pair#token=...`) and the desktop deep link (`t3code://pair?pairingUrl=...`).

## Daily CLI commands

```sh
t3fleet status [--sandbox <name>] [--usage] [--json]
t3fleet ssh [--sandbox <name>] [-- <command>...]
t3fleet wake [--sandbox <name>]
t3fleet stop [--sandbox <name>]
t3fleet connect [--sandbox <name>] [--port 13773] [--no-tunnel]
t3fleet sync                              # sync SSH config fragments for all your sandboxes
```

### Multiple sandboxes per user (optional)

Users get a `"default"` sandbox (`t3fleet-<user>`), and can optionally create additional named sandboxes (up to `--max-sandboxes-per-user`, default `5`; set `1` to disable extra sandboxes):

```sh
t3fleet sandbox new billing --size default
t3fleet sandbox list
t3fleet ssh --sandbox billing             # or SSH host t3fleet-alice-billing in T3 Code
t3fleet sandbox rm billing
```

### Templates (Boat saved snapshots)

To pre-bake T3 Code, toolchains, repositories, or a T3 managed policy (`/etc/t3code/policy.json`) into a reusable snapshot:

```sh
BOAT_API_KEY=boat_... ./scripts/build-template.sh team-base \
  --type small \
  --setup ./your-setup.sh \
  --policy ./policy.json
```

Then start the server with `--default-template team-base` (or pass `--template team-base` on `admin user create` / `t3fleet sandbox new`). Sandboxes booted from a snapshot that already has `t3` and an active `t3code.service` skip re-installation on boot.

### Admin commands

```sh
t3fleet admin user create <user> [--size small|default|large] [--template <name>] [--no-provision]
t3fleet admin user list [--json]
t3fleet admin user invite <user>          # issue another single-use invite (e.g. second laptop)
t3fleet admin user revoke <user>          # revoke all active device API tokens for a user
t3fleet admin user delete <user> [--delete-sandbox]
t3fleet admin sandbox wake|stop <user> [--sandbox <name>]
t3fleet admin usage [--json]              # lightweight Boat runtime & cost summary
```

## Auto-stop, auto-wake & snapshot retention

The watchdog (`--watch-interval-secs`, default `60`) probes running sandboxes over Boat's command API and reads both OS state and T3 Code's `statev2.sqlite` (read-only):

- **Protected work signals (never interrupted):** queued/running turns (`projection_turns`), active sessions (`projection_thread_sessions`), streaming responses (`projection_thread_messages`), active `provider-processes/*.json` subprocesses, and remote interactive SSH PTYs (`pts/*`).
- **Safety TTL:** while active, the server extends Boat's TTL (`--safety-ttl-secs`, default `7200`s) before it nears expiry so long background agents finish, while ensuring a crashed control plane cannot leak a VM indefinitely. Failed probes never trigger a stop.
- **14-day retention guard:** Boat retains ordinary stopped disks for at least 14 days. By default (`--snapshot-retention-days 13`, `0` to disable), the watchdog automatically saves a Boat saved snapshot (`t3fleet-keep-...`) for any sandbox still stopped past day 13, transparently recreates from it if the original disk later expires (`409 snapshot_data_expired`), and deletes the temporary saved snapshot once the sandbox is active again.
- **Wake policies (`--wake-policy` / `T3FLEET_WAKE_POLICY`):**
  - `auto` *(default)* — keeps sandboxes alive while active work *or* an SSH/T3 socket is open; auto-stops once disconnected and idle (`--idle-timeout-secs`, default `900`s); auto-wakes on `ssh-proxy` unless manually stopped (`t3fleet stop`) or within `--auto-wake-cooldown-secs` (`120`s).
  - `aggressive-idle` — stops idle sandboxes even if T3 Desktop left an idle tunnel open (keeps alive only on active work, PTYs, or recent thread activity); passive `ssh-proxy` refuses to wake stopped boxes to avoid wake/sleep loops, and users wake explicitly via `t3fleet wake` / `ssh` / `connect`.
  - `explicit` — work-aware auto-stop; wakes only on explicit CLI commands.

## Security model

- `BOAT_API_KEY` lives only on `t3fleet-server`; every sandbox is created with `noEnv: true`.
- Enrollment tokens and per-device API tokens are 256-bit random values stored only as SHA-256 hashes in SQLite and compared in constant time.
- Employee endpoints derive ownership strictly from the device bearer token.
- `t3fleet join` and `t3fleet admin` reject plain HTTP outside loopback (`127.0.0.1`/`::1`/`localhost`) and Tailscale CGNAT (`100.64.0.0/10`) unless `--allow-insecure-http` is passed.
- OpenSSH connects with `StrictHostKeyChecking yes` against an isolated `known_hosts` file updated atomically from Boat's authenticated API response on every connect.
- Note on revocation: `admin user revoke` immediately blocks future API/SSH ticket requests; to also cut an already-open SSH session immediately, run `admin sandbox stop <user>`.

## Current limitations

- **Stock T3 Desktop auto-reconnect vs. idle stop:** T3 Code Desktop's connection supervisor retries disconnected SSH environments with exponential backoff while enabled, and OpenSSH gives `ProxyCommand` no way to tell a background retry apart from an intentional user reconnect. Use `--wake-policy auto` if users close T3 Desktop when done, or `--wake-policy aggressive-idle` (explicit `t3fleet wake`) if users leave T3 Desktop open all day.
- **One manual click in T3 Desktop:** `t3fleet join` writes the SSH alias so T3 Desktop discovers it automatically, but adding the environment still requires selecting it once in **Settings → Environments → Add environment → SSH** (or using `t3fleet connect`).
- **Provider logins inside sandboxes:** Agent providers (`claude`, `codex`, etc.) are authenticated inside each sandbox (or provisioned via your template/managed policy), just like any remote T3 Code machine.

## Repository layout

```text
crates/
  t3fleet-protocol/   Shared HTTP request/response types
  t3fleet-server/     Axum + SQLite control plane, SandboxProvider trait, Boat adapter, watchdog
  t3fleet-cli/        Cross-platform CLI (employee + admin + SSH ProxyCommand)
docs/
  providers.md        SandboxProvider trait contract and capability model
scripts/
  build-template.sh   Build and save a reusable Boat saved snapshot
  live-e2e.sh         Live end-to-end test against boat.dev + isolated Docker clients
deploy/               Example systemd unit and Caddyfile
install.sh            Linux / macOS one-liner installer
install.ps1           Windows PowerShell one-liner installer
Dockerfile            Container build for t3fleet-server
```

## Testing

**Isolated unit & integration suite (no Boat credentials or host `~/.ssh`/`~/.t3` touched):**
```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

**Live end-to-end test against real `boat.dev` using isolated Docker client containers:**
```sh
BOAT_API_KEY=boat_... ./scripts/live-e2e.sh
```

## License

[MIT](LICENSE)
