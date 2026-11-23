# Sandbox Providers

`t3fleet-server` isolates cloud/VM backend operations behind the [`SandboxProvider`](../crates/t3fleet-server/src/provider.rs) trait and registers implementations in `ProviderRegistry`. Today only **`boat`** ([`crates/t3fleet-server/src/providers/boat.rs`](../crates/t3fleet-server/src/providers/boat.rs)) is implemented; the interface is designed so other VM or container backends can plug in without modifying the control plane, SQLite lifecycle, or CLI.

## Core trait (`SandboxProvider`)

Every provider implements a small, normalized surface:

- **Identity & metadata:** `name() -> &'static str`, `capabilities() -> ProviderCapabilities`, `guest_user() -> GuestUser` (username + home directory used for T3 Code systemd bootstrap, `statev2.sqlite` idle probing, and client SSH config).
- **Lifecycle:** `create(CreateSandboxSpec)`, `get(id)`, `wait_for(id, stopped)` *(default polling impl)*, `resume(id, lease_ttl_secs) -> ResumeOutcome`, `suspend(id)`, `delete(id)`.
- **Access & execution:**
  - `authorize_ssh(id, public_key) -> SshAccess { host, port, ssh_user, host_key: Option<String>, sandbox_id }`
  - `exec(id, command, timeout) -> String` (runs a shell command inside the sandbox for bootstrap and idle checks).

Provider-specific states are normalized into `SandboxState`: `Starting`, `Running`, `Stopping`, `Stopped`, `Failed`.

## Optional capabilities (`ProviderCapabilities`)

Backends differ significantly in how they handle billing leases, disk retention, templates, and metering, so those are gated behind explicit capability flags with safe no-op defaults:

| Capability | Default method | Boat (`boat.dev`) | Example: durable-pause VMs (e.g. `freestyle.sh`, Incus) |
| --- | --- | --- | --- |
| `lease_ttl` | `extend_lease` → `Ok(())` | `true` (`PATCH /sandboxes/{id}` `ttlSeconds`) | `false` (no rolling auto-stop lease needed) |
| `snapshot_retention` | `save_snapshot` / `saved_snapshot` / `delete_saved_snapshot` | `true` (preserves stopped disks before 14-day cleanup) | `false` (paused/stopped disks persist durably) |
| `usage_reporting` | `usage` → `Ok(None)` | `true` (`GET /sandboxes/{id}/usage`) | `false` unless backend exposes per-VM metering |
| `templates` | `CreateSandboxSpec.template` | `true` (`from` saved snapshot) | `true` if base snapshot/image cloning is supported |

## How different backends map onto the interface

- **`boat.dev` (implemented):** `guest_user` is `user` (`/home/user`), `suspend` maps to `POST /stop`, `resume` returns `ResumeOutcome::Expired` on `409 snapshot_data_expired`, and `authorize_ssh` injects the user's Ed25519 key via `/sshkey` and returns `host_key: Some(...)` so `t3fleet ssh-proxy` pins rotating host keys with `StrictHostKeyChecking yes`.
- **Durable-pause VM providers (e.g. `freestyle.sh`):** `guest_user` maps to the image user (such as `ubuntu` / `/home/ubuntu`), `suspend` maps to VM pause/hibernate, `resume` always returns `ResumeOutcome::Ready`, `lease_ttl` and `snapshot_retention` stay `false`, and `authorize_ssh` can return `host_key: None` when connecting through a stable SSH gateway.
- **Self-hosted VM/container hosts (e.g. Incus, Docker, raw VPS):** `exec` runs over the local host daemon or a server-side admin SSH key, `authorize_ssh` writes the user's public key to `authorized_keys`, and `suspend`/`resume` stop and start the guest.

## Adding a new provider

1. Implement `SandboxProvider` in `crates/t3fleet-server/src/providers/<name>.rs`.
2. Register it in `ProviderRegistry` inside `crates/t3fleet-server/src/lib.rs` / `main.rs` (wired via `--provider <name>` or per-provider config).
3. Add an integration test against `App::open_with_providers(...)` (see the `StubProvider` test in [`crates/t3fleet-cli/tests/fleet.rs`](../crates/t3fleet-cli/tests/fleet.rs)).
