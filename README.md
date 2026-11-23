# t3fleet

Team sandbox management for [T3 Code](https://t3.codes), powered by [boat.dev](https://boat.dev).

`t3fleet` lets a team run isolated cloud sandboxes for every developer using stock T3 Code, with no fork, no public HTTP ports, and no paying for idle machines 24/7.

## Why use t3fleet

**For admins and team leads**
- **One-command onboarding:** Provision an isolated sandbox per developer and send a single-use invite token.
- **Standardized environments:** Bake your repos, toolchains, and T3 managed policy into a reusable Boat snapshot template so every developer starts with the same setup.
- **Private by default:** `BOAT_API_KEY` stays on the control plane, every sandbox runs with `noEnv: true`, and T3 Code binds only to `127.0.0.1:3773` behind per-user SSH keys.
- **Automatic cost control:** Idle sandboxes stop automatically without interrupting running background agents, and stopped disks are automatically saved before Boat's 14-day retention window expires.
- **Central control:** Revoke a device token, stop or wake a sandbox, or check per-sandbox usage from one CLI.

**For developers**
- **Works with stock T3 Code:** Run `t3fleet join` once. Your SSH host is configured automatically and shows up in T3 Code Desktop's SSH environment picker. Add it once and T3 Code reconnects by itself.
- **Agents keep working when you disconnect:** Long-running turns continue in the cloud even if you close your laptop; the sandbox only stops once work finishes and sits idle.
- **Zero SSH babysitting:** Boat rotates sandbox IPs and host keys on resume. `t3fleet` handles waking the machine and pinning the fresh host key automatically.
- **Optional extra sandboxes:** Spin up a separate box for a branch or experiment (`t3fleet sandbox new billing`) and remove it when done.

## Install

**macOS & Linux (client CLI):**
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

Prebuilt binaries for Linux (`x86_64`, `aarch64`), macOS (`arm64`, `x86_64`), and Windows (`x86_64`) are published on [GitHub Releases](https://github.com/abaudhuin/t3fleet/releases).

## Getting started

### 1. Admin: start the server & invite a user

Run `t3fleet-server` on any small always-on host (for example, on Tailscale or behind Caddy/HTTPS; see [Dockerfile](Dockerfile) and [deploy/](deploy/)):

```sh
BOAT_API_KEY=boat_... t3fleet-server --listen 127.0.0.1:8080 --db ./t3fleet.db
```

On first boot without `T3FLEET_ADMIN_TOKEN`, the server generates an admin token, prints it once to stderr, and stores only its hash in SQLite.

Create a user and share the printed single-use `enr_...` token:

```sh
export T3FLEET_SERVER=https://fleet.example.com   # or your Tailscale IP
export T3FLEET_ADMIN_TOKEN=adm_...

t3fleet admin user create alice --size small
```

### 2. Developer: join & add to T3 Code

```sh
t3fleet join --server https://fleet.example.com --token enr_...
```

`join` creates a dedicated SSH keypair, enrolls your machine, and registers your SSH host (`t3fleet-alice`) in `~/.ssh/config`.

Then add the host to T3 Code Desktop once:

1. On the Welcome screen, click **Start without an agent**. Your agent runs in the sandbox, so it does not need setup on your machine.
2. Open **Settings → Environments → Add environment → SSH**.
3. Select `t3fleet-alice`, then click **Add environment**.
4. In a new thread, choose your sandbox under **Run on**.

T3 Code manages this connection itself. No terminal has to stay open, and reopening the app reconnects and wakes a sandbox that stopped while idle. After a manual `t3fleet stop`, run `t3fleet wake` first.

On Linux, T3 Code Desktop saves connections in the system keyring. A minimal desktop without a Secret Service such as `gnome-keyring` fails with "Could not register connection".

## Everyday commands

### Developer

```sh
t3fleet status [--sandbox <name>] [--usage] [--json]
t3fleet ssh [--sandbox <name>] [-- <command>...]
t3fleet wake [--sandbox <name>]
t3fleet stop [--sandbox <name>]
t3fleet sync                              # refresh local SSH entries for all your sandboxes
```

**Multiple sandboxes (optional):** Users can spin up additional named sandboxes (up to `--max-sandboxes-per-user`, default `5`; set `1` to keep one sandbox per user):

```sh
t3fleet sandbox new billing --size default
t3fleet sandbox list
t3fleet ssh --sandbox billing             # SSH host: t3fleet-alice-billing
t3fleet sandbox rm billing
```

### Admin

```sh
t3fleet admin user create <user> [--size small|default|large] [--template <name>] [--no-provision]
t3fleet admin user list [--json]
t3fleet admin user invite <user>          # issue another single-use invite (e.g. second laptop)
t3fleet admin user revoke <user>          # revoke active device tokens for a user
t3fleet admin user delete <user> [--delete-sandbox]
t3fleet admin sandbox wake|stop <user> [--sandbox <name>]
t3fleet admin usage [--json]              # Boat runtime and cost summary
```

## Team templates

To give every new sandbox the same tools, repositories, or T3 managed policy (`/etc/t3code/policy.json`), build a reusable Boat saved snapshot once:

```sh
BOAT_API_KEY=boat_... ./scripts/build-template.sh team-base \
  --type small \
  --setup ./your-setup.sh \
  --policy ./policy.json
```

Start the server with `--default-template team-base` (or pass `--template team-base` per user or sandbox). T3 Code is already installed in the snapshot, so new sandboxes skip re-installation.

`build-template.sh` removes T3 Code's environment ID, signing keys, and database before saving, keeping only `settings.json` and `keybindings.json`, so each sandbox generates its own identity on first boot. **Rebuild templates made with an earlier version**, because their sandboxes share those secrets.

To try T3 Code with no provider login, [`scripts/templates/opencode.sh`](scripts/templates/opencode.sh) enables OpenCode with a free default model:

```sh
BOAT_API_KEY=boat_... ./scripts/build-template.sh team-base --setup ./scripts/templates/opencode.sh
```

## Auto-stop, wake policies & snapshot retention

`t3fleet-server` checks running sandboxes every minute (`--watch-interval-secs`) and never stops a box while a T3 agent turn, streaming response, provider subprocess, or interactive SSH shell is active. When a box is active, the server automatically extends Boat's safety TTL (`--safety-ttl-secs`, default `7200`s) so long jobs are never cut off.

Choose how aggressively idle boxes stop and wake with `--wake-policy` (`T3FLEET_WAKE_POLICY`):

- **`auto` *(default)*:** Stops sandboxes once disconnected and idle (`--idle-timeout-secs`, default 15 minutes). Wakes automatically when you reconnect over SSH, while respecting manual `t3fleet stop` and a short anti-flap cooldown (`--auto-wake-cooldown-secs`, default 2 minutes). Best when developers close T3 Code or sleep their laptops between sessions.
- **`aggressive-idle`:** Stops idle sandboxes even if T3 Code Desktop is left open in the background with no active turns or recent thread activity. Passive SSH reconnects will not wake the box (preventing reconnect wake loops); wake explicitly with `t3fleet wake` or `t3fleet ssh`.
- **`explicit`:** Same work-aware auto-stop, and wakes only on explicit CLI commands.

**14-day retention safety net:** By default (`--snapshot-retention-days 13`, `0` to disable), any sandbox stopped past day 13 is automatically saved to a Boat saved snapshot, transparently restored if the original stopped disk expires, and cleaned up once the sandbox is running again.

## Security & known caveats

- **Private transport & least privilege:** Only `t3fleet-server` holds `BOAT_API_KEY`. Sandboxes are created with `noEnv: true`, T3 Code listens only on loopback (`127.0.0.1:3773`), SSH traffic goes directly from the developer's laptop to their sandbox with strict host-key pinning, and all server tokens are stored as SHA-256 hashes. Plain HTTP is blocked outside loopback and Tailscale unless `--allow-insecure-http` is passed.
- **Revocation:** `admin user revoke` blocks new API/SSH ticket requests immediately; run `admin sandbox stop <user>` to also terminate an already-open SSH session.
- **T3 Desktop setup & reconnects:** T3 Desktop discovers enrolled SSH hosts automatically, but each developer adds theirs once in **Settings → Environments → Add environment → SSH**. Because OpenSSH cannot distinguish T3 Desktop's background reconnect retries from a manual click, use `--wake-policy aggressive-idle` if your team leaves T3 Desktop open all day.
- **Provider logins:** Coding agent providers (`claude`, `codex`, etc.) are authenticated inside each sandbox or configured via your template/policy, same as any remote T3 Code host.

## Providers & development

`t3fleet-server` talks to backends through a pluggable `SandboxProvider` trait (`boat.dev` is implemented today). See [docs/providers.md](docs/providers.md) for the trait contract and capability model.

```sh
# Isolated test suite (no Boat credentials or host ~/.ssh / ~/.t3 touched)
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Live end-to-end test against boat.dev using isolated Docker clients
BOAT_API_KEY=boat_... ./scripts/live-e2e.sh
```

## License

[MIT](LICENSE)
