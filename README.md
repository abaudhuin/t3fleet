# t3fleet

t3fleet gives each employee a Boat sandbox for T3 Code. The Rust workspace contains the shared HTTP protocol, an Axum control plane backed by SQLite, and a CLI for employees and admins. Run one control-plane instance per database.

## Quickstart

Install both binaries from the workspace root. The CLI uses OpenSSH and ssh-keygen on Unix.

```sh
cargo install --path crates/t3fleet-server
cargo install --path crates/t3fleet-cli
```

Set `BOAT_API_KEY` in the server environment. Set `BOAT_ORG` if your Boat account requires it. Start the control plane with a persistent database path.

```sh
t3fleet-server --db ./t3fleet.db
```

The default listener is `127.0.0.1:8080`. When initializing the database, the server prints a generated admin token once unless you supply `T3FLEET_ADMIN_TOKEN`. Save the generated token before sharing server access. For remote enrollment, publish the control plane behind HTTPS or on a Tailscale IP.

In your admin shell, set `T3FLEET_SERVER` and `T3FLEET_ADMIN_TOKEN`, then create a user. Send the resulting single-use token to the employee privately.

```sh
t3fleet admin user create alice
t3fleet admin user invite alice
```

Use `invite` for a second device or to replace an expired token. Usernames start with a lowercase letter or digit, followed by lowercase letters, digits, hyphens or underscores, up to 48 characters total. If immediate provisioning fails, the user is retained so an admin can retry with `t3fleet admin sandbox wake alice` and issue a new invite.

The employee enrolls, then can inspect or manage their sandbox.

```sh
t3fleet join --server https://fleet.example.com --token "$INVITE"
t3fleet status
t3fleet ssh
t3fleet stop
t3fleet wake
```

## Connect to T3 Code

- **Desktop over SSH.** Select the SSH option in T3 Code Desktop and enter the alias printed by `join`, such as `t3fleet-alice`. Enrollment installs an OpenSSH include and uses a dedicated Ed25519 identity. It defaults to the platform configuration directory and `~/.ssh/config`. Use `join --config-dir` and `--ssh-config` to choose alternate paths, and `--config /path/to/config.toml` on subsequent CLI commands when using a custom config directory.
- **Pair over a local tunnel.** Run `t3fleet connect`. Open one of the printed pairing links and keep the terminal open while connected. The default local port is `13773`. With `--no-tunnel`, provide your own SSH forward from the chosen local port to port `3773` on the sandbox.

The server installs and starts T3 Code on the sandbox's loopback interface. The CLI writes the host key obtained over the authenticated control plane before relaying the SSH connection. OpenSSH verifies that key with strict host key checking.

## Credentials and lifecycle

The Boat API key stays on the control plane. SQLite stores SHA-256 hashes of bearer tokens and invitations. Employee endpoints derive sandbox ownership from the device token. Local credentials and the SSH identity are stored with mode `0600`. Join permits HTTP on localhost, loopback or Tailscale IPs, and otherwise requires HTTPS or explicit `--allow-insecure-http`.

Admins can use `user revoke` to invalidate all existing device API tokens for a user. Revocation prevents future ticket requests and leaves already authorized SSH keys and established sessions in place. Use `sandbox stop` to stop the sandbox, or `user delete --delete-sandbox` to remove it from Boat as well as from t3fleet.

## Auto-start, auto-stop & wake policies

The watchdog checks each running sandbox every minute by default (`--watch-interval-secs`, default `60`). It inspects both OS state and T3 Code's `statev2.sqlite` (read-only):

- **Hard work signals (never interrupted):** running/queued turns (`projection_turns`), active agent sessions (`projection_thread_sessions`), streaming responses (`projection_thread_messages`), active provider subprocesses (`provider-processes`), and interactive SSH PTYs (`who`).
- **Connection signals:** established SSH (`:22`) and T3 HTTP/WS (`:3773`) sockets.
- **Safety TTL:** when active, `t3fleet-server` extends Boat's safety TTL (`--safety-ttl-secs`, default `7200`) before it nears expiry so long-running background agents are not killed, while ensuring a crashed server can never leak a VM forever.
- **Fail-safe:** if the activity probe fails transiently, the watchdog skips stopping.
- **Boat warm-stop window:** Boat stops billing immediately on `stop` and keeps the warm VM unbilled for ~10 minutes (fast resume with memory/processes intact), after which resume boots cleanly from snapshot and `systemd` restarts `t3code.service` automatically.

Because stock OpenSSH gives `ProxyCommand` the same invocation whether a user clicked reconnect or T3 Code Desktop's background connection supervisor retried, `t3fleet-server` supports three explicit `--wake-policy` (`T3FLEET_WAKE_POLICY`) modes:

- **`auto` (default):** keeps sandboxes alive while work *or* an SSH/T3 connection is open; auto-stops when disconnected and idle for `--idle-timeout-secs` (default `900`s). Passive `ssh-proxy` auto-wakes stopped sandboxes unless manually stopped (`t3fleet stop`) or within `--auto-wake-cooldown-secs` (default `120`s). Best when users close T3 Desktop / sleep laptops when finished.
- **`aggressive-idle`:** keeps sandboxes alive *only* on real agent work, interactive PTYs, or recent T3 thread activity—so an idle T3 Desktop window left open overnight still auto-stops to save compute. Passive `ssh-proxy` refuses to wake stopped sandboxes (preventing T3 Desktop's infinite backoff reconnect loop from re-waking idle boxes); users wake explicitly with `t3fleet wake`, `t3fleet ssh`, or `t3fleet connect`.
- **`explicit`:** same work-aware auto-stop, and only wakes on explicit CLI commands (`wake`, `ssh`, `connect`).

`sandboxes` in SQLite are keyed by `(user_id, name)` (defaulting to `"default"`), ready for future multi-sandbox-per-user support without schema breakage.

## Isolated tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Integration tests use an in-process Boat HTTP mock, a loopback TCP echo server, temporary SQLite databases and temporary CLI and SSH configuration directories. They require `ssh-keygen` and `ssh` and use no real Boat credentials or T3 Code service.
