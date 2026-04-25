#!/usr/bin/env bash
# test/09-bootstrap.sh — wipe the test Pi and re-install the agent via the
# release install.sh, then assert the device shows up online + v2 in the api.
#
# Prereqs: env OBACHT_USER_JWT (admin) and OBACHT_DEVICE_ID set; ssh access
# to pi@raspberrypi.local; release.yml has published a release under
# OBACHT_AGENT_VERSION (default: latest).
#
# Usage:
#   OBACHT_USER_JWT=eyJ... OBACHT_DEVICE_ID=ba585791-... ./test/09-bootstrap.sh

set -euo pipefail

PI_HOST="${OBACHT_PI_HOST:-pi@raspberrypi.local}"
API_URL="${OBACHT_API_URL:-https://api.eu.obacht.dev}"
DEVICE_ID="${OBACHT_DEVICE_ID:?OBACHT_DEVICE_ID required}"
USER_JWT="${OBACHT_USER_JWT:?OBACHT_USER_JWT required (admin/owner of device)}"
VERSION="${OBACHT_AGENT_VERSION:-latest}"
REPO="${OBACHT_AGENT_REPO:-obacht-dev/obacht-agent}"

say() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }

say "issuing install token for $DEVICE_ID via api"
TOKEN_RESP="$(curl -fsS -X POST \
  -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: application/json' \
  "$API_URL/devices/$DEVICE_ID/install-token?force=true")"
INSTALL_TOKEN="$(echo "$TOKEN_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
[ -n "$INSTALL_TOKEN" ] || { echo "failed to mint install token: $TOKEN_RESP" >&2; exit 1; }

say "wiping previous install on $PI_HOST"
ssh "$PI_HOST" sudo bash -s <<'WIPE'
set -eux
systemctl stop obacht-agent.service 2>/dev/null || true
systemctl disable obacht-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/obacht-agent.service
systemctl daemon-reload
rm -rf /opt/obacht-agent /etc/obacht /var/lib/obacht/agent-v2.db /run/obacht
docker ps -aq --filter label=obacht.managed=1 | xargs -r docker rm -f
WIPE

if [ "$VERSION" = "latest" ]; then
  INSTALL_SH_URL="https://github.com/$REPO/releases/latest/download/install.sh"
else
  INSTALL_SH_URL="https://github.com/$REPO/releases/download/$VERSION/install.sh"
fi

say "running install.sh on $PI_HOST"
ssh "$PI_HOST" sudo bash -s -- \
  --device-id "$DEVICE_ID" \
  --token "$INSTALL_TOKEN" \
  --api-url "$API_URL" \
  --version "$VERSION" \
  < <(curl -fsSL "$INSTALL_SH_URL")

say "verifying device is registered as v2 in api"
sleep 5
DEV_JSON="$(curl -fsS -H "Authorization: Bearer $USER_JWT" "$API_URL/devices/$DEVICE_ID")"
echo "$DEV_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d.get("agent_v2") is True, f"agent_v2 not set: {d}"
print("agent_version:", d.get("agent_version"))
print("agent_last_seen:", d.get("agent_last_seen"))
'

say "bootstrap test passed"
