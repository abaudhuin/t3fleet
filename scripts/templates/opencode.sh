#!/usr/bin/env bash
# Template setup: enable OpenCode in T3 Code with a free model that needs no login.
#
# Usage:
#   BOAT_API_KEY=boat_... ./scripts/build-template.sh team-base \
#     --setup ./scripts/templates/opencode.sh
#
# OpenCode's free model list changes over time. Run `opencode models` in a
# sandbox and update DEFAULT_MODEL if this one is no longer offered.
set -euo pipefail

DEFAULT_MODEL="opencode/deepseek-v4.1-flash-free"
SETTINGS=/home/user/.t3/userdata/settings.json

command -v opencode >/dev/null || {
  echo "opencode is not installed in this image" >&2
  exit 1
}

sudo install -d -o user -g user -m 700 /home/user/.t3 /home/user/.t3/userdata
sudo python3 - "$SETTINGS" "$DEFAULT_MODEL" <<'PY'
import json, os, sys

path, model = sys.argv[1:3]
settings = {}
if os.path.exists(path):
    with open(path, encoding="utf-8") as f:
        settings = json.load(f)
settings.setdefault("providerInstances", {})["opencode"] = {
    "driver": "opencode",
    "displayName": "OpenCode",
    "enabled": True,
}
settings["defaultModelSelection"] = {"instanceId": "opencode", "model": model}
with open(path, "w", encoding="utf-8") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PY
sudo chown user:user "$SETTINGS"
sudo chmod 600 "$SETTINGS"
