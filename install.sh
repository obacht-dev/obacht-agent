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
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" /var/log/obacht
# Ensure INSTALL_DIR is traversable — a previous failed install may have left
# it at 0700 (leaked umask). Fix idempotently on every run.
chmod 0755 "$INSTALL_DIR"
tar -xzf "$tmpdir/$asset" -C "$tmpdir"
src_dir="$(find "$tmpdir" -maxdepth 1 -type d -name 'obacht-agent_*' | head -1)"
install -m 0755 "$src_dir/obacht-agent" "$INSTALL_DIR/obacht-agent"
install -m 0755 "$src_dir/obachtctl"    "$INSTALL_DIR/obachtctl" 2>/dev/null || true
# S5: privileged helper. Lives outside INSTALL_DIR because the
# bootstrap sudoers fragment pins this exact path; moving it would
# require a coordinated sudoers update.
if [ -f "$src_dir/obacht-power-toggle" ]; then
  install -m 0755 "$src_dir/obacht-power-toggle" /usr/local/sbin/obacht-power-toggle
fi

# ---------------------------------------------------------------------------
# S5: create the unprivileged `obacht` user that the agent runs as.
#
# Why: if the agent itself is compromised (the most likely surface — it
# talks to the network and runs untrusted manifest configs), we want
# the blast radius to be the docker daemon and a tightly-scoped
# sudoers entry, NOT free root on the host.
#
# The user is added with --no-create-home (we use $STATE_DIR instead)
# and slotted into the docker group so it can run containers, plus
# systemd-journal so journalctl works for diagnostics.
# ---------------------------------------------------------------------------
if ! id -u obacht >/dev/null 2>&1; then
  echo "==> creating unprivileged user 'obacht'"
  useradd --system --no-create-home --shell /usr/sbin/nologin \
          --home-dir "$STATE_DIR" obacht
fi
# Idempotent group adds (errors-on-already-member, hence the || true).
usermod -a -G docker obacht || true
if getent group systemd-journal >/dev/null 2>&1; then
  usermod -a -G systemd-journal obacht || true
fi
chown -R obacht:obacht "$STATE_DIR" "$RUNTIME_DIR"
chown obacht:obacht "$CONFIG_DIR"
# S6.5: the unix-domain socket /run/obacht/agent-v2.sock is mode 0660
# (obacht:obacht), which is correct for the daemon but means obachtctl
# invocations over SSH must run as a user that is in the `obacht`
# group. The ssh-gateway connects as the operator's SSH login (e.g.
# `pi`), so we add SUDO_USER to the obacht group on every install.
# Idempotent: usermod -a -G is a no-op when already a member.
# Override via OBACHT_SSH_USER env, falling back to SUDO_USER, falling
# back to nothing (user added pi manually).
ssh_user="${OBACHT_SSH_USER:-${SUDO_USER:-}}"
if [ -n "$ssh_user" ] && [ "$ssh_user" != "root" ] && id -u "$ssh_user" >/dev/null 2>&1; then
  echo "==> adding $ssh_user to obacht group (for obachtctl IPC over SSH)"
  usermod -a -G obacht "$ssh_user" || true
fi
# S1/S5: audit log lives under /var/log/obacht. Owned by obacht so the
# unprivileged agent can append; group `adm` (when present) lets ops
# read the log without sudo, mirroring journald conventions.
log_group="obacht"
if getent group adm >/dev/null 2>&1; then log_group="adm"; fi
chown -R "obacht:$log_group" /var/log/obacht
chmod 0750 /var/log/obacht

# ---------------------------------------------------------------------------
# S5.4: scrub the v1 NOPASSWD:ALL sudoers fragment if it's still around.
# v1 (Python agent) installed `/etc/sudoers.d/obacht` with full passwordless
# root — exactly the blast radius v2 is designed to remove. We drop it on
# every v2 install so a Pi that gets re-bootstrapped is immediately back to
# restricted-by-default, even if the operator forgets to wipe /etc.
# ---------------------------------------------------------------------------
if [ -f /etc/sudoers.d/obacht ]; then
  echo "==> removing legacy /etc/sudoers.d/obacht (v1 NOPASSWD:ALL)"
  rm -f /etc/sudoers.d/obacht
fi
# Same for the older Power Mode fragment — obacht-power-toggle is the
# canonical writer now; if it's there from a previous v2 run it gets
# rewritten by `obachtctl system unlock-power`. Removing it here means
# fresh installs always start LOCKED.
if [ -f /etc/sudoers.d/obacht-power ]; then
  echo "==> removing /etc/sudoers.d/obacht-power (start locked)"
  rm -f /etc/sudoers.d/obacht-power
fi

# ---------------------------------------------------------------------------
# S5: bootstrap sudoers fragment. The ONLY thing the obacht user is
# allowed to run as root is /usr/local/sbin/obacht-power-toggle, with
# its two fixed argv values. Power-level templates can only run after
# the operator deliberately enables Power Mode — see PLAN-AGENT-V2 S5.
# ---------------------------------------------------------------------------
if [ -x /usr/local/sbin/obacht-power-toggle ]; then
  echo "==> writing /etc/sudoers.d/obacht-bootstrap"
  tmp_sudoers="$(mktemp)"
  cat > "$tmp_sudoers" <<'SUDO'
# Managed by obacht-agent install.sh. Do not edit by hand.
# Phase S5: lets the unprivileged `obacht` user flip Power Mode on/off
# via a fixed-content helper (see /usr/local/sbin/obacht-power-toggle).
# This is the ONLY sudoers grant the agent gets at install time.
obacht ALL=(root) NOPASSWD: /usr/local/sbin/obacht-power-toggle enable
obacht ALL=(root) NOPASSWD: /usr/local/sbin/obacht-power-toggle disable
SUDO
  chmod 0440 "$tmp_sudoers"
  if command -v visudo >/dev/null 2>&1; then
    visudo -c -f "$tmp_sudoers" >/dev/null
  fi
  mv "$tmp_sudoers" /etc/sudoers.d/obacht-bootstrap
fi


echo "==> writing $CONFIG_FILE"
# umask in a subshell so we don't leave the rest of the install with 0077
# (the systemd unit, sudoers fragment etc. would otherwise come out 0600
# instead of the intended 0644/0440).
( umask 077
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
)
chmod 0600 "$CONFIG_FILE"
# S5: bootstrap exchange rewrites this file (token -> JWT), so the
# unprivileged agent must own it. CONFIG_DIR ownership was set above.
chown obacht:obacht "$CONFIG_FILE"

echo "==> installing systemd unit"
cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=Obacht Pi Agent v2
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
# S5: drop privileges. The agent does not need root for its core job
# (Docker via group membership, Caddy as a child process binding
# unprivileged ports first then handed elevated caps via systemd).
# The only privileged action — flipping Power Mode — goes through the
# obacht-power-toggle binary via the bootstrap sudoers entry.
User=obacht
Group=obacht
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

# Wait up to ~120s for the agent to come up + connect. Cold first boot on a
# slow SD card can take 30–60s just to JIT-init the Go runtime + open the
# WebSocket against the api, so the previous 30s budget was too tight on
# real hardware. Tolerate both JSON-structured (`"msg":"ws connected"`)
# and plain (`ws connected`) log lines so a logger format change doesn't
# silently turn this check into an exit-1.
echo "==> waiting for agent to come online (up to 120s)"
ok=0
for i in $(seq 1 60); do
  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    if journalctl -u "$SERVICE_NAME" --since "180 seconds ago" --no-pager 2>/dev/null \
        | grep -qE '("msg":"ws connected"|ws connected)'; then
      ok=1
      break
    fi
  fi
done

if [ "$ok" -ne 1 ]; then
  echo "agent did not connect within 120s — last 40 log lines:" >&2
  journalctl -u "$SERVICE_NAME" --no-pager -n 40 >&2 || true
  echo "check 'journalctl -u $SERVICE_NAME -f' for ongoing retries" >&2
  exit 1
fi

echo "==> obacht-agent $RELEASE_TAG installed and connected"
