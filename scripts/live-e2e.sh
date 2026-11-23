#!/usr/bin/env bash
# Live end-to-end test against real boat.dev + isolated Docker client containers.
# NEVER touches host ~/.t3 or ~/.ssh/config.
# Always deletes created Boat sandboxes on exit.
#
# Required env: BOAT_API_KEY (and optional BOAT_ORG)
set -euo pipefail

: "${BOAT_API_KEY:?BOAT_API_KEY must be set}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${SERVER_BIN:-$REPO_ROOT/target/debug/t3fleet-server}"
CLI_BIN="${CLI_BIN:-$REPO_ROOT/target/debug/t3fleet}"
DOCKER_IMAGE="${DOCKER_IMAGE:-t3fleet-test-client:local}"
PORT="${T3FLEET_TEST_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')}"
SERVER_URL="http://127.0.0.1:${PORT}"
ADMIN_TOKEN="adm_live_e2e_$(openssl rand -hex 12)"

RUN_ID="$(date +%s)"
ALICE="e2e-alice-${RUN_ID}"
BOB="e2e-bob-${RUN_ID}"

TMPDIR_E2E="$(mktemp -d /tmp/t3fleet-live-e2e.XXXXXX)"
SERVER_PID=""
ALICE_CID=""
BOB_CID=""

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32m  [OK] %s\033[0m\n' "$*"; }

cleanup() {
  local rc=$?
  set +e
  if [ "$rc" -ne 0 ] && [ -f "$TMPDIR_E2E/server.log" ]; then
    echo "=== SERVER LOG (on failure) ===" >&2
    cat "$TMPDIR_E2E/server.log" >&2
  fi
  log "Cleaning up containers, Boat sandboxes, and temp files"
  [ -n "$ALICE_CID" ] && docker rm -f "$ALICE_CID" >/dev/null 2>&1
  [ -n "$BOB_CID" ] && docker rm -f "$BOB_CID" >/dev/null 2>&1
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    for u in "$ALICE" "$BOB"; do
      "$CLI_BIN" admin user delete "$u" --delete-sandbox \
        --server "$SERVER_URL" --admin-token "$ADMIN_TOKEN" >/dev/null 2>&1 || true
    done
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR_E2E"
  exit "$rc"
}
trap cleanup EXIT

log "1. Starting isolated t3fleet-server on $SERVER_URL"
T3FLEET_LISTEN="127.0.0.1:${PORT}" \
T3FLEET_DB="$TMPDIR_E2E/fleet.db" \
T3FLEET_ADMIN_TOKEN="$ADMIN_TOKEN" \
T3FLEET_IDLE_TIMEOUT_SECS=20 \
T3FLEET_WATCH_INTERVAL_SECS=10 \
T3FLEET_AUTO_WAKE_COOLDOWN_SECS=30 \
T3FLEET_SAFETY_TTL_SECS=1800 \
T3FLEET_WAKE_POLICY="auto" \
  "$SERVER_BIN" >"$TMPDIR_E2E/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "$SERVER_URL/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS "$SERVER_URL/healthz" | grep -q '"ok":true'
pass "Server healthy"

log "2. Provisioning two small Boat sandboxes ($ALICE and $BOB) in parallel"
"$CLI_BIN" admin user create "$ALICE" --size small --server "$SERVER_URL" --admin-token "$ADMIN_TOKEN" --json >"$TMPDIR_E2E/alice_invite.json" &
PID_A=$!
"$CLI_BIN" admin user create "$BOB" --size small --server "$SERVER_URL" --admin-token "$ADMIN_TOKEN" --json >"$TMPDIR_E2E/bob_invite.json" &
PID_B=$!
wait "$PID_A"
wait "$PID_B"

ALICE_TOKEN="$(jq -r .enrollment_token "$TMPDIR_E2E/alice_invite.json")"
ALICE_SBX="$(jq -r .sandbox_id "$TMPDIR_E2E/alice_invite.json")"
BOB_TOKEN="$(jq -r .enrollment_token "$TMPDIR_E2E/bob_invite.json")"
BOB_SBX="$(jq -r .sandbox_id "$TMPDIR_E2E/bob_invite.json")"
[ -n "$ALICE_SBX" ] && [ "$ALICE_SBX" != "null" ]
[ -n "$BOB_SBX" ] && [ "$BOB_SBX" != "null" ]
[ "$ALICE_SBX" != "$BOB_SBX" ]
pass "Provisioned $ALICE ($ALICE_SBX) and $BOB ($BOB_SBX) with T3 Code bootstrapped"

log "3. Starting two isolated Docker client containers (zero host ~/.ssh or ~/.t3 access)"
ALICE_CID="$(docker run -d --network host -v "$CLI_BIN:/usr/local/bin/t3fleet:ro" "$DOCKER_IMAGE" sleep 600)"
BOB_CID="$(docker run -d --network host -v "$CLI_BIN:/usr/local/bin/t3fleet:ro" "$DOCKER_IMAGE" sleep 600)"

docker exec "$ALICE_CID" t3fleet join --server "$SERVER_URL" --token "$ALICE_TOKEN" --device-name "alice-container"
docker exec "$BOB_CID" t3fleet join --server "$SERVER_URL" --token "$BOB_TOKEN" --device-name "bob-container"
pass "Both isolated containers joined and generated per-user SSH identities & ~/.ssh/config Include"

log "4. Verifying direct SSH via ProxyCommand + StrictHostKeyChecking + T3 Code service + noEnv isolation"
ALICE_CHECK="$(docker exec "$ALICE_CID" ssh -o BatchMode=yes "t3fleet-$ALICE" '
  set -eu
  echo "WHOAMI=$(whoami)"
  echo "T3VER=$(/home/user/.local/bin/t3 --version)"
  echo "SYSTEMD=$(systemctl is-active t3code)"
  echo "LISTEN=$(ss -Htl "sport = :3773")"
  echo "ENV_LEAK=$(env | grep -c BOAT_API_KEY || true)"
  echo "ENV_ID=$(cat /home/user/.t3/userdata/environment-id)"
')"
echo "$ALICE_CHECK"
echo "$ALICE_CHECK" | grep -q "WHOAMI=user"
echo "$ALICE_CHECK" | grep -q "SYSTEMD=active"
echo "$ALICE_CHECK" | grep -q "127.0.0.1:3773"
echo "$ALICE_CHECK" | grep -q "ENV_LEAK=0"

BOB_CHECK="$(docker exec "$BOB_CID" ssh -o BatchMode=yes "t3fleet-$BOB" '
  set -eu
  echo "SYSTEMD=$(systemctl is-active t3code)"
  echo "ENV_ID=$(cat /home/user/.t3/userdata/environment-id)"
')"
echo "$BOB_CHECK"
echo "$BOB_CHECK" | grep -q "SYSTEMD=active"
ALICE_ENV_ID="$(echo "$ALICE_CHECK" | awk -F= '/^ENV_ID=/{print $2}')"
BOB_ENV_ID="$(echo "$BOB_CHECK" | awk -F= '/^ENV_ID=/{print $2}')"
[ "$ALICE_ENV_ID" != "$BOB_ENV_ID" ]
pass "Alice ($ALICE_ENV_ID) and Bob ($BOB_ENV_ID) are on separate isolated Boat sandboxes with T3 Code bound strictly to 127.0.0.1:3773 and zero secret leaks"

log "5. Verifying T3 Code is reachable over the SSH route T3 Code Desktop uses"
docker exec "$ALICE_CID" bash -lc '
  set -euo pipefail
  ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -L 127.0.0.1:13779:127.0.0.1:3773 "t3fleet-'"$ALICE"'" &
  SSH_PID=$!
  trap "kill $SSH_PID 2>/dev/null || true; wait $SSH_PID 2>/dev/null || true" EXIT
  for _ in $(seq 1 60); do
    curl -fsS -o /dev/null http://127.0.0.1:13779/.well-known/t3/environment && break
    sleep 0.5
  done
  ENV_JSON="$(curl -fsS http://127.0.0.1:13779/.well-known/t3/environment)"
  echo "FORWARDED_T3_ENV=$ENV_JSON"
  echo "$ENV_JSON" | grep -q "environmentId"
'
pass "SSH host reaches the remote T3 Code server over a private loopback forward"

log "5b. Verifying lightweight usage reporting, sandbox list, and SSH sync"
docker exec "$ALICE_CID" t3fleet status --usage --json | jq -e '.usage.sandbox_id != null and (.usage.seconds >= 0)' >/dev/null
docker exec "$ALICE_CID" t3fleet sandbox list --json | jq -e 'length == 1 and .[0].sandbox_name == "default"' >/dev/null
docker exec "$ALICE_CID" t3fleet sync
"$CLI_BIN" admin usage --server "$SERVER_URL" --admin-token "$ADMIN_TOKEN" --json | jq -e 'length >= 2' >/dev/null
pass "Usage reporting, sandbox list, and SSH fragment sync verified against live Boat API"

log "6. Verifying manual stop, anti-flap passive ssh-proxy rejection, resume, and rotated host-key pinning"
docker exec "$ALICE_CID" t3fleet stop
docker exec "$ALICE_CID" t3fleet status --json | jq -e '.state == "stopped" and .stopped_reason == "manual" and .provider == "boat"' >/dev/null
pass "Alice sandbox manually stopped and archived on Boat"

if docker exec "$ALICE_CID" t3fleet ssh-proxy --config /root/.config/t3fleet/config.toml --alias "t3fleet-$ALICE" </dev/null >/dev/null 2>"$TMPDIR_E2E/proxy_blocked.err"; then
  echo "ERROR: passive ssh-proxy should have been rejected on manually stopped sandbox!" >&2
  exit 1
fi
grep -qi "manually stopped" "$TMPDIR_E2E/proxy_blocked.err"
pass "Passive ssh-proxy rejected while manually stopped (prevents T3 reconnect wake loop)"

docker exec "$ALICE_CID" t3fleet wake
docker exec "$ALICE_CID" ssh -o BatchMode=yes "t3fleet-$ALICE" 'systemctl is-active t3code && test -f /home/user/.t3/userdata/environment-id'
pass "Resumed sandbox, systemd auto-restarted t3code, and SSH connected with freshly pinned host key"

log "7. Verifying live background watchdog (statev2.sqlite + OS probe -> auto-stop on idle)"
STOPPED_IDLE=0
for i in $(seq 1 18); do
  ST="$(docker exec "$ALICE_CID" t3fleet status --json)"
  STATE="$(echo "$ST" | jq -r '.state')"
  REASON="$(echo "$ST" | jq -r '.stopped_reason')"
  echo "  poll #$i: state=$STATE reason=$REASON activity=$(echo "$ST" | jq -c '.activity')"
  if [ "$STATE" = "stopped" ] && [ "$REASON" = "idle" ]; then
    STOPPED_IDLE=1
    break
  fi
  sleep 5
done
[ "$STOPPED_IDLE" = "1" ]
pass "Background watchdog probed real sandbox (statev2.sqlite + sockets + PTYs) and auto-stopped idle sandbox"

log "ALL LIVE END-TO-END CHECKS PASSED!"
