#!/usr/bin/env bash
# Build and save a reusable Boat saved snapshot with T3 Code preinstalled
# (plus an optional custom setup script for repos, toolchains, or T3 policy).
#
# Usage:
#   BOAT_API_KEY=... ./scripts/build-template.sh <template-name> [options]
#
# Options:
#   --type <small|default|large>  Machine size for build sandbox (default: small)
#   --setup <path/to/script.sh>   Optional setup script executed inside the sandbox as user
#   --policy <path/to/policy.json> Optional T3 managed policy installed to /etc/t3code/policy.json
#   --api-base <url>              Boat API base (default: https://boat.dev/api/v1)
#
# Environment:
#   BOAT_API_KEY  Required Boat API token
#   BOAT_ORG      Optional Boat org header (X-Boat-Org)
set -euo pipefail

: "${BOAT_API_KEY:?BOAT_API_KEY must be set}"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <template-name> [--type small|default|large] [--setup script.sh] [--policy policy.json]" >&2
  exit 1
fi

TEMPLATE_NAME="$1"
shift

SIZE="small"
SETUP_SCRIPT=""
POLICY_FILE=""
API_BASE="${BOAT_API_BASE:-https://boat.dev/api/v1}"

while [ $# -gt 0 ]; do
  case "$1" in
    --type)     SIZE="$2"; shift 2 ;;
    --setup)    SETUP_SCRIPT="$2"; shift 2 ;;
    --policy)   POLICY_FILE="$2"; shift 2 ;;
    --api-base) API_BASE="$2"; shift 2 ;;
    *)          echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if ! printf '%s' "$TEMPLATE_NAME" | grep -Eq '^[a-z0-9][a-z0-9-]{0,62}$'; then
  echo "Template name must match ^[a-z0-9][a-z0-9-]{0,62}$" >&2
  exit 1
fi

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

HEADERS=(-H "Authorization: Bearer ${BOAT_API_KEY}" -H "Content-Type: application/json")
if [ -n "${BOAT_ORG:-}" ]; then
  HEADERS+=(-H "X-Boat-Org: ${BOAT_ORG}")
fi

SANDBOX_ID=""
cleanup() {
  local rc=$?
  set +e
  if [ -n "$SANDBOX_ID" ]; then
    echo "==> Deleting temporary build sandbox ${SANDBOX_ID}"
    curl -fsS -X DELETE "${API_BASE}/sandboxes/${SANDBOX_ID}" \
      "${HEADERS[@]}" \
      -H "X-Ascii-Confirm-Delete: ${SANDBOX_ID}" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

run_cmd() {
  local cmd="$1"
  local timeout="${2:-300}"
  local payload resp ok exit_code
  payload="$(jq -nc --arg c "$cmd" --argjson t "$timeout" '{command: $c, timeoutSeconds: $t}')"
  resp="$(curl -fsS -X POST "${API_BASE}/sandboxes/${SANDBOX_ID}/commands" "${HEADERS[@]}" -d "$payload")"
  ok="$(echo "$resp" | jq -r '.ok and .success and (.exitCode == 0) and (.timedOut | not)')"
  if [ "$ok" != "true" ]; then
    echo "Command failed inside ${SANDBOX_ID}:" >&2
    echo "$resp" | jq -r '.stderr // .stdout // .' >&2
    exit 1
  fi
}

echo "==> Creating temporary build sandbox (type=${SIZE}, noEnv=true)"
CREATE_BODY="$(jq -nc --arg t "$SIZE" --arg n "t3fleet-template-${TEMPLATE_NAME}" \
  '{type: $t, noEnv: true, ttlSeconds: 1800, name: $n, labels: {"t3fleet.template": "true"}}')"
SANDBOX_ID="$(curl -fsS -X POST "${API_BASE}/sandboxes" "${HEADERS[@]}" -d "$CREATE_BODY" | jq -r '.sandbox.id')"
echo "    sandbox: ${SANDBOX_ID}"

echo "==> Waiting for sandbox to become ready"
for _ in $(seq 1 90); do
  STATE="$(curl -fsS "${API_BASE}/sandboxes/${SANDBOX_ID}" "${HEADERS[@]}" | jq -r '.sandbox.state')"
  case "$STATE" in
    ready|idle|running) break ;;
    error|cancelled) echo "Sandbox entered terminal state: ${STATE}" >&2; exit 1 ;;
  esac
  sleep 2
done

echo "==> Installing T3 Code and enabling persistent systemd unit"
run_cmd 'set -eu
if [ ! -x /home/user/.local/bin/t3 ]; then
  if [ "$(id -un)" = "user" ]; then
    env HOME=/home/user bash -o pipefail -c "curl -fsSL https://t3.codes/install.sh | sh"
  else
    sudo -u user env HOME=/home/user bash -o pipefail -c "curl -fsSL https://t3.codes/install.sh | sh"
  fi
fi
sudo tee /etc/profile.d/t3fleet.sh >/dev/null <<"PROFILE"
export PATH="/home/user/.local/bin:$PATH"
PROFILE
sudo tee /etc/systemd/system/t3code.service >/dev/null <<"SERVICE"
[Unit]
Description=T3 Code
After=network-online.target
Wants=network-online.target

[Service]
User=user
Environment=HOME=/home/user
Environment=T3CODE_HOME=/home/user/.t3
Environment=PATH=/home/user/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=/home/user
ExecStart=/home/user/.local/bin/t3 serve --host 127.0.0.1 --port 3773
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload
sudo systemctl enable --now t3code
timeout 25 sh -c "until ss -Htl \"sport = :3773\" 2>/dev/null | grep -q .; do sleep 1; done"
' 300

if [ -n "$POLICY_FILE" ]; then
  echo "==> Installing T3 managed policy from ${POLICY_FILE}"
  POLICY_B64="$(base64 -w 0 "$POLICY_FILE" 2>/dev/null || base64 "$POLICY_FILE" | tr -d '\n')"
  run_cmd "set -eu; sudo mkdir -p /etc/t3code; printf '%s' '${POLICY_B64}' | base64 -d | sudo tee /etc/t3code/policy.json >/dev/null; sudo chmod 0644 /etc/t3code/policy.json; sudo systemctl restart t3code" 60
fi

if [ -n "$SETUP_SCRIPT" ]; then
  echo "==> Running custom setup script ${SETUP_SCRIPT}"
  SETUP_B64="$(base64 -w 0 "$SETUP_SCRIPT" 2>/dev/null || base64 "$SETUP_SCRIPT" | tr -d '\n')"
  run_cmd "set -eu; tmp=\$(mktemp); printf '%s' '${SETUP_B64}' | base64 -d > \"\$tmp\"; chmod +x \"\$tmp\"; bash \"\$tmp\"; rm -f \"\$tmp\"" 600
fi

# A snapshot must not carry T3 Code's identity: every sandbox restored from it
# would share one environment ID and the same server signing keys.
echo "==> Removing T3 Code identity and runtime state from the template"
run_cmd 'set -eu
sudo systemctl stop t3code
sudo find /home/user/.t3/userdata -mindepth 1 -maxdepth 1 ! -name settings.json ! -name keybindings.json -exec rm -rf {} +
sudo systemctl enable t3code >/dev/null 2>&1
sync
' 60

echo "==> Saving Boat saved snapshot '${TEMPLATE_NAME}'"
SAVE_BODY="$(jq -nc --arg id "$SANDBOX_ID" --arg name "$TEMPLATE_NAME" '{sandboxId: $id, name: $name}')"
curl -fsS -X POST "${API_BASE}/saved-snapshots" "${HEADERS[@]}" -d "$SAVE_BODY" >/dev/null

echo "==> Waiting for saved snapshot '${TEMPLATE_NAME}' to become ready"
for _ in $(seq 1 180); do
  SNAP_RESP="$(curl -fsS "${API_BASE}/saved-snapshots/${TEMPLATE_NAME}" "${HEADERS[@]}")"
  SNAP_STATUS="$(echo "$SNAP_RESP" | jq -r '.snapshot.status')"
  case "$SNAP_STATUS" in
    ready)
      echo "==> Saved snapshot '${TEMPLATE_NAME}' is ready!"
      echo "Use with: t3fleet-server --default-template ${TEMPLATE_NAME}"
      echo "Or:       t3fleet admin user create alice --template ${TEMPLATE_NAME}"
      echo "Or:       t3fleet sandbox new feat-x --template ${TEMPLATE_NAME}"
      exit 0
      ;;
    failed)
      echo "Saved snapshot failed: $(echo "$SNAP_RESP" | jq -r '.snapshot.error // "unknown"')" >&2
      exit 1
      ;;
  esac
  sleep 2
done

echo "Timed out waiting for saved snapshot '${TEMPLATE_NAME}'" >&2
exit 1
