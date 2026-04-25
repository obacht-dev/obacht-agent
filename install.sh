#!/usr/bin/env bash
# obacht-agent bootstrap installer.
#
#   curl -fsSL https://github.com/obacht-dev/obacht-agent/releases/latest/download/install.sh \
#     | sudo bash -s -- \
#         --device-id <uuid> \
#         --token     <install-token> \
#         --api-url   https://api.eu.obacht.dev
#
# What this does, in order:
#   1. Verify deps (docker, systemd, curl, tar)
#   2. Resolve the latest agent release for the host's GOOS/GOARCH
#   3. Download + verify (sha256) the tarball into /opt/obacht-agent/
#   4. Write /etc/obacht/agent-v2.yml with the install token
#   5. Install + enable the systemd unit
#   6. Wait for the agent to validate the install token with the api
#
# Designed to be safely re-runnable: re-running upgrades the binary in place.

set -euo pipefail

REPO="${OBACHT_AGENT_REPO:-obacht-dev/obacht-agent}"
RELEASE_TAG="${OBACHT_AGENT_VERSION:-latest}"
INSTALL_DIR="/opt/obacht-agent"
CONFIG_DIR="/etc/obacht"
CONFIG_FILE="$CONFIG_DIR/agent-v2.yml"
STATE_DIR="/var/lib/obacht"
RUNTIME_DIR="/run/obacht"
SERVICE_NAME="obacht-agent.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"

DEVICE_ID=""
TOKEN=""
API_URL="https://api.eu.obacht.dev"
SKIP_START="${OBACHT_AGENT_SKIP_START:-0}"

usage() {
  cat <<USAGE
obacht-agent installer

  --device-id   <uuid>   device id (required)
  --token       <token>  one-time install token (required)
  --api-url     <url>    api base url (default: $API_URL)
  --version     <tag>    release tag (default: latest)
  --help                 show this help

env:
  OBACHT_AGENT_REPO=$REPO
  OBACHT_AGENT_VERSION=$RELEASE_TAG
  OBACHT_AGENT_SKIP_START=0|1   skip 'systemctl start' (for tests)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --device-id) DEVICE_ID="$2"; shift 2 ;;
    --token)     TOKEN="$2";     shift 2 ;;
    --api-url)   API_URL="$2";   shift 2 ;;
    --version)   RELEASE_TAG="$2"; shift 2 ;;
    --help|-h)   usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root (sudo)" >&2
  exit 1
fi
if [ -z "$DEVICE_ID" ] || [ -z "$TOKEN" ]; then
  echo "--device-id and --token are required" >&2
  usage >&2
  exit 2
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need curl
need tar
need sha256sum
need systemctl
need docker

uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$uname_s" in
  linux) goos="linux" ;;
  darwin) goos="darwin" ;;
  *) echo "unsupported os: $uname_s" >&2; exit 1 ;;
esac
uname_m="$(uname -m)"
case "$uname_m" in
  x86_64|amd64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  armv7l|armv7) goarch="armv7" ;;
  *) echo "unsupported arch: $uname_m" >&2; exit 1 ;;
esac

if [ "$RELEASE_TAG" = "latest" ]; then
  resolved_tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$resolved_tag" ]; then
    echo "failed to resolve latest release for $REPO" >&2
    exit 1
  fi
  RELEASE_TAG="$resolved_tag"
fi

asset="obacht-agent_${RELEASE_TAG}_${goos}_${goarch}.tar.gz"
base_url="https://github.com/$REPO/releases/download/$RELEASE_TAG"

echo "==> downloading $asset"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL -o "$tmpdir/$asset"        "$base_url/$asset"
curl -fsSL -o "$tmpdir/$asset.sha256" "$base_url/$asset.sha256"

echo "==> verifying checksum"
( cd "$tmpdir" && sha256sum -c "$asset.sha256" )

echo "==> installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR"
tar -xzf "$tmpdir/$asset" -C "$tmpdir"
src_dir="$(find "$tmpdir" -maxdepth 1 -type d -name 'obacht-agent_*' | head -1)"
install -m 0755 "$src_dir/obacht-agent" "$INSTALL_DIR/obacht-agent"
install -m 0755 "$src_dir/obachtctl"    "$INSTALL_DIR/obachtctl" 2>/dev/null || true

echo "==> writing $CONFIG_FILE"
umask 077
cat > "$CONFIG_FILE" <<YAML
# Managed by obacht-agent install.sh — overwritten on re-install.
server:
  url: $API_URL
  deviceId: $DEVICE_ID
  # The bootstrap exchanges this one-time install-token for a long-lived
  # device JWT on first connect; the agent persists the JWT back into this
  # file, replacing the install token.
  authToken: $TOKEN
registry:
  url: https://registry.eu.obacht.dev
paths:
  stateDb: $STATE_DIR/agent-v2.db
  socket: $RUNTIME_DIR/agent-v2.sock
  caddyData: $STATE_DIR/caddy/data
  caddyConfig: $STATE_DIR/caddy/config
YAML
chmod 0600 "$CONFIG_FILE"

echo "==> installing systemd unit"
cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=Obacht Pi Agent v2
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/obacht-agent -config $CONFIG_FILE
Restart=always
RestartSec=3
RuntimeDirectory=obacht
RuntimeDirectoryMode=0755
StateDirectory=obacht
StateDirectoryMode=0750

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

if [ "$SKIP_START" = "1" ]; then
  echo "==> SKIP_START=1 set, not starting service"
  exit 0
fi

echo "==> starting $SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "==> waiting for agent to come online"
ok=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    if journalctl -u "$SERVICE_NAME" --since "60 seconds ago" --no-pager 2>/dev/null \
        | grep -q '"msg":"ws connected"'; then
      ok=1
      break
    fi
  fi
done

if [ "$ok" -ne 1 ]; then
  echo "agent did not connect within timeout — check 'journalctl -u $SERVICE_NAME'" >&2
  exit 1
fi

echo "==> obacht-agent $RELEASE_TAG installed and connected"
