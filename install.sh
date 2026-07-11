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
REGISTRY_URL="https://registry.eu.obacht.dev"
SKIP_START="${OBACHT_AGENT_SKIP_START:-0}"
USER_SIGNING_PUBKEY="${OBACHT_USER_SIGNING_PUBKEY:-}"

usage() {
  cat <<USAGE
obacht-agent installer

  --device-id      <uuid>   device id (required)
  --token          <token>  one-time install token (required)
  --api-url        <url>    api base url (default: $API_URL)
  --registry-url   <url>    template registry url (default: $REGISTRY_URL)
  --version        <tag>    release tag (default: latest)
  --user-pubkey    <line>   OpenSSH ed25519 public key to pin for signed
                            mutations (optional; env OBACHT_USER_SIGNING_PUBKEY)
  --help                    show this help

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
    --registry-url) REGISTRY_URL="$2"; shift 2 ;;
    --version)   RELEASE_TAG="$2"; shift 2 ;;
    --user-pubkey) USER_SIGNING_PUBKEY="$2"; shift 2 ;;
    --self-update) SELF_UPDATE=1; shift 1 ;;
    --help|-h)   usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root (sudo)" >&2
  exit 1
fi
# In --self-update mode we re-use the existing /etc/obacht/agent-v2.yml
# (device id + token already provisioned). Skip the required-args check.
if [ "${SELF_UPDATE:-0}" = "1" ]; then
  if [ ! -f "$CONFIG_FILE" ]; then
    echo "--self-update requires an existing $CONFIG_FILE" >&2
    exit 2
  fi
  # Pull current device-id + token from the YAML so the rest of the
  # install script (which writes the config) regenerates the same
  # values. Cheap parsing - config is owned by us.
  DEVICE_ID="${DEVICE_ID:-$(awk '/^[[:space:]]*deviceId:/{print $2; exit}' "$CONFIG_FILE")}"
  TOKEN="${TOKEN:-$(awk '/^[[:space:]]*authToken:/{print $2; exit}' "$CONFIG_FILE")}"
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

# Signed-release verification (defence beyond sha256, which comes from the
# same GitHub release). The minisig is verified by the CURRENTLY installed,
# already-trusted agent binary against its EMBEDDED offline release key -
# NOT by the freshly-downloaded code - so a compromised release publisher
# cannot bypass the check. Exit codes from `obacht-agent verify-release`:
#   0 verified  / 1 signature REJECTED (abort)  / 2 cannot verify (migration).
# On a fresh install there is no prior binary to anchor trust in, so this
# is a self-update-only gate; fresh installs rest on TLS + sha256 (TOFU),
# unchanged.
#
# CRITICAL GUARD (VERIFY_SUPPORT_MARKER): only invoke `verify-release` when
# the CURRENTLY installed binary actually implements that subcommand. Agents
# released before this feature (<= v0.4.0) treat "verify-release" as an
# unknown positional, fall through to flag.Parse and START THE DAEMON - which
# would hang the update and disrupt the running agent's socket. The marker is
# written (below) only by a verify-capable install.sh right after it installs
# a verify-capable binary, so its presence <=> the installed binary supports
# the check. Forward-only fleet, so downgrades (which would leave a stale
# marker) are out of scope; a manual downgrade must remove the marker.
installed_agent="$INSTALL_DIR/obacht-agent"
VERIFY_SUPPORT_MARKER="$INSTALL_DIR/.verify-release-supported"
if [ "${SELF_UPDATE:-0}" = "1" ] && [ -x "$installed_agent" ] && [ -f "$VERIFY_SUPPORT_MARKER" ]; then
  if curl -fsSL -o "$tmpdir/$asset.minisig" "$base_url/$asset.minisig" 2>/dev/null; then
    echo "==> verifying release signature"
    set +e
    "$installed_agent" verify-release --file "$tmpdir/$asset" --sig "$tmpdir/$asset.minisig"
    vr=$?
    set -e
    case "$vr" in
      0) : ;;  # verified
      1) echo "FATAL: release signature REJECTED - refusing to self-update" >&2; exit 1 ;;
      *) echo "WARN: could not verify release signature (unsigned-migration); continuing on sha256" >&2 ;;
    esac
  else
    echo "WARN: no .minisig for $asset (unsigned release); continuing on sha256" >&2
  fi
elif [ "${SELF_UPDATE:-0}" = "1" ]; then
  echo "==> installed agent predates signed releases; skipping signature check (sha256 only)"
fi

echo "==> installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" /var/log/obacht
# Ensure INSTALL_DIR is traversable - a previous failed install may have left
# it at 0700 (leaked umask). Fix idempotently on every run.
chmod 0755 "$INSTALL_DIR"
tar -xzf "$tmpdir/$asset" -C "$tmpdir"
src_dir="$(find "$tmpdir" -maxdepth 1 -type d -name 'obacht-agent_*' | head -1)"
install -m 0755 "$src_dir/obacht-agent" "$INSTALL_DIR/obacht-agent"
install -m 0755 "$src_dir/obachtctl"    "$INSTALL_DIR/obachtctl" 2>/dev/null || true
# Mark that the just-installed binary implements `verify-release`, so the
# NEXT self-update knows it may safely invoke it (see VERIFY_SUPPORT_MARKER
# above). This install.sh only ships verify-capable binaries, hence the
# unconditional write. Presence of this marker <=> installed binary supports
# signature verification.
: > "$INSTALL_DIR/.verify-release-supported"
# S6.5: symlink obachtctl into PATH so the ssh-gateway can invoke it
# by name (without a hard-coded absolute path). Idempotent - ln -sf
# overwrites any stale symlink left by a previous install.
ln -sf "$INSTALL_DIR/obachtctl" /usr/local/bin/obachtctl
# S5: privileged helper. Lives outside INSTALL_DIR because the
# bootstrap sudoers fragment pins this exact path; moving it would
# require a coordinated sudoers update.
if [ -f "$src_dir/obacht-power-toggle" ]; then
  install -m 0755 "$src_dir/obacht-power-toggle" /usr/local/sbin/obacht-power-toggle
fi

# S5: privileged self-update wrapper. Same trust model as
# obacht-power-toggle: a fixed-content shell script at a pinned path,
# allowed via sudoers. Lets the obacht user (and through it, the
# webapp via ssh-gateway -> obachtctl) re-run this very installer to
# upgrade the agent in place.
echo "==> writing /usr/local/sbin/obacht-self-update"
cat > /usr/local/sbin/obacht-self-update <<'SELF'
#!/usr/bin/env bash
# Managed by obacht-agent install.sh - fixed content. Only argv is the
# release tag (or "latest").
#
# The freshly-downloaded install.sh is verified against the EMBEDDED
# offline release key by the CURRENTLY installed (trusted) agent binary
# BEFORE it is executed. Without this, a compromised release publisher
# could ship an install.sh that simply skips the tarball check. This
# wrapper is the trust anchor: it is a fixed-content file on the device
# (pinned by sudoers), not re-downloaded, and it refuses to run an
# install.sh whose signature is rejected.
set -euo pipefail
ver="${1:-latest}"
case "$ver" in
  latest|v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "obacht-self-update: invalid version $ver" >&2; exit 2 ;;
esac
if [ "$ver" = "latest" ]; then
  base="https://github.com/obacht-dev/obacht-agent/releases/latest/download"
else
  base="https://github.com/obacht-dev/obacht-agent/releases/download/${ver}"
fi
url="$base/install.sh"
echo "==> obacht-self-update: fetching $url"
tmp="$(mktemp)"; tmpsig="$(mktemp)"
trap 'rm -f "$tmp" "$tmpsig"' EXIT
curl -fsSL -o "$tmp" "$url"

# Anchor: verify install.sh with the installed agent's embedded release key.
# 0 verified  / 1 REJECTED (abort)  / 2 cannot verify (unsigned-migration).
# Guard: only call verify-release when the installed binary supports it
# (marker written by install.sh right after installing a capable binary).
# Agents <= v0.4.0 lack the subcommand and would start the daemon + hang.
installed_agent="/opt/obacht-agent/obacht-agent"
if [ -x "$installed_agent" ] && [ -f /opt/obacht-agent/.verify-release-supported ] \
   && curl -fsSL -o "$tmpsig" "$url.minisig" 2>/dev/null; then
  set +e
  "$installed_agent" verify-release --file "$tmp" --sig "$tmpsig"
  vr=$?
  set -e
  case "$vr" in
    0) echo "==> obacht-self-update: install.sh signature OK" ;;
    1) echo "FATAL: install.sh signature REJECTED - aborting self-update" >&2; exit 1 ;;
    *) echo "WARN: could not verify install.sh signature (unsigned-migration); continuing" >&2 ;;
  esac
else
  echo "WARN: install.sh signature not verified (old agent, unsigned release, or no anchor); continuing" >&2
fi

chmod +x "$tmp"
OBACHT_AGENT_VERSION="$ver" bash "$tmp" --self-update
SELF
chmod 0755 /usr/local/sbin/obacht-self-update

# ---------------------------------------------------------------------------
# S5: create the unprivileged `obacht` user that the agent runs as.
#
# Why: if the agent itself is compromised (the most likely surface - it
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
# root - exactly the blast radius v2 is designed to remove. We drop it on
# every v2 install so a Pi that gets re-bootstrapped is immediately back to
# restricted-by-default, even if the operator forgets to wipe /etc.
# ---------------------------------------------------------------------------
if [ -f /etc/sudoers.d/obacht ]; then
  echo "==> removing legacy /etc/sudoers.d/obacht (v1 NOPASSWD:ALL)"
  rm -f /etc/sudoers.d/obacht
fi
# Same for the older Power Mode fragment - obacht-power-toggle is the
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
# the operator deliberately enables Power Mode - see PLAN-AGENT-V2 S5.
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
# Phase F3: lets the same user trigger an in-place upgrade by re-running
# install.sh. The helper accepts a version tag (or "latest") as its
# only argv and downloads + verifies install.sh from the pinned GitHub
# release URL. Sudoers wildcard scopes to a single argv whose value
# is whitelisted inside the helper itself.
obacht ALL=(root) NOPASSWD: /usr/local/sbin/obacht-self-update *
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
# Managed by obacht-agent install.sh - overwritten on re-install.
server:
  url: $API_URL
  deviceId: $DEVICE_ID
  # The bootstrap exchanges this one-time install-token for a long-lived
  # device JWT on first connect; the agent persists the JWT back into this
  # file, replacing the install token.
  authToken: $TOKEN
registry:
  url: $REGISTRY_URL
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

# Signed mutations (PLAN-PI-SIGNED-MUTATIONS A3): pin the user's signing
# pubkey BEFORE the agent first starts, so the device advertises the
# signed-mutation capability from its very first agent:register. Same
# TOFU trust level as the authorized_keys line the platform install
# script provisions - it is the same key.
if [ -n "$USER_SIGNING_PUBKEY" ]; then
  case "$USER_SIGNING_PUBKEY" in
    ssh-ed25519\ *)
      echo "==> pinning user signing key for signed mutations"
      install -d -m 0700 -o obacht -g obacht "$STATE_DIR/user-keys.d"
      ( umask 077; printf '%s\n' "$USER_SIGNING_PUBKEY" > "$STATE_DIR/user-keys.d/default.pub" )
      chown obacht:obacht "$STATE_DIR/user-keys.d/default.pub"
      ;;
    *)
      echo "WARN: --user-pubkey is not an ssh-ed25519 line, skipping pin" >&2
      ;;
  esac
fi

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
# The only privileged action - flipping Power Mode - goes through the
# obacht-power-toggle binary via the bootstrap sudoers entry.
User=obacht
Group=obacht
# Bind-mount dirs for templates are pre-created by the agent and must be
# writable by the container's runtime uid (often non-root, e.g. grafana=472)
# AND by the agent's own file-browser. The agent owns the dir but needs
# CAP_CHOWN to hand ownership to the container uid (and CAP_FOWNER to fix a
# pre-existing root-owned dir). This adds no real privilege: the agent is in
# the docker group and can already launch privileged containers.
AmbientCapabilities=CAP_CHOWN CAP_FOWNER
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
# slow SD card can take 30-60s just to JIT-init the Go runtime + open the
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
  echo "agent did not connect within 120s - last 40 log lines:" >&2
  journalctl -u "$SERVICE_NAME" --no-pager -n 40 >&2 || true
  echo "check 'journalctl -u $SERVICE_NAME -f' for ongoing retries" >&2
  exit 1
fi

echo "==> obacht-agent $RELEASE_TAG installed and connected"
