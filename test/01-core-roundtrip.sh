#!/usr/bin/env bash
# 01-core-roundtrip.sh — exercises the v2 agent's core control loop on the
# real test pi. Validates: cross-build → scp → install docker (if missing) →
# upsert instance → reconcile → HTTP probe → remove → reconcile → cleaned up.
#
# Idempotent: re-running stops any previous attempt and starts fresh.
#
# Requires: ssh access to PI_HOST (default pi@raspberrypi.local), local
# `go` toolchain, `curl`, `ssh`, `scp`.
set -euo pipefail

PI_HOST="${PI_HOST:-pi@raspberrypi.local}"
PI_HTTP_HOST="${PI_HTTP_HOST:-raspberrypi.local}"
PORT="${PORT:-18080}"
INSTANCE_ID="${INSTANCE_ID:-roundtrip-1}"
TEMPLATE_ID="${TEMPLATE_ID:-nginx-roundtrip}"
REMOTE_DIR="/tmp/obacht-agent-test"
REMOTE_DB="${REMOTE_DIR}/agent.db"
REMOTE_CFG="${REMOTE_DIR}/agent.yml"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s ===\n' "$*"; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

say "1/8 cross-build linux/arm64"
mkdir -p build
GOOS=linux GOARCH=arm64 go build -trimpath -o build/obacht-agent-linux-arm64 ./cmd/obacht-agent
GOOS=linux GOARCH=arm64 go build -trimpath -o build/obachtctl-linux-arm64   ./cmd/obachtctl

say "2/8 ensure remote workspace"
ssh "$PI_HOST" "set -e; sudo mkdir -p '$REMOTE_DIR' && sudo chown \$(id -u):\$(id -g) '$REMOTE_DIR'"
scp -q build/obacht-agent-linux-arm64 build/obachtctl-linux-arm64 "$PI_HOST:$REMOTE_DIR/"
ssh "$PI_HOST" "chmod +x '$REMOTE_DIR/obacht-agent-linux-arm64' '$REMOTE_DIR/obachtctl-linux-arm64'"

say "3/8 ensure docker is installed and running on pi"
ssh "$PI_HOST" 'set -e
if ! command -v docker >/dev/null 2>&1; then
  echo "installing docker..."
  sudo apt-get update -qq
  sudo apt-get install -yq docker.io
fi
sudo systemctl enable --now docker
sudo usermod -aG docker $(whoami) || true
sudo docker version --format "Server: {{.Server.Version}}" '

say "4/8 write minimal agent.yml + reset DB"
ssh "$PI_HOST" "rm -f '$REMOTE_DB'; cat > '$REMOTE_CFG' <<EOF
paths:
  stateDb: $REMOTE_DB
EOF"

say "5/8 upsert instance via obachtctl"
ssh "$PI_HOST" "'$REMOTE_DIR/obachtctl-linux-arm64' --db='$REMOTE_DB' instance upsert \
  --id='$INSTANCE_ID' --template='$TEMPLATE_ID' --runtime=container --state=installed \
  --version=1.0.0 --config-file=- <<'JSON'
{\"image\":\"nginx:alpine\",\"ports\":[{\"host\":$PORT,\"container\":80}]}
JSON"

say "6/8 reconcile once (apply) — needs sudo for docker.sock"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obacht-agent-linux-arm64' -config='$REMOTE_CFG' -once" || die "reconcile (apply) failed"

say "7/8 verify container is up and serving HTTP"
ssh "$PI_HOST" "sudo docker ps --filter label=obacht.instance.id=$INSTANCE_ID --format '{{.Names}} {{.Status}} {{.Ports}}'"
# Wait briefly for nginx to bind.
for i in 1 2 3 4 5; do
  if curl -fsS -o /dev/null "http://$PI_HTTP_HOST:$PORT/"; then
    echo "HTTP OK on http://$PI_HTTP_HOST:$PORT/"
    break
  fi
  echo "HTTP retry $i..."; sleep 2
done
curl -fsS -o /dev/null "http://$PI_HTTP_HOST:$PORT/" || die "HTTP probe failed"

say "8/8 remove and reconcile — container should disappear"
ssh "$PI_HOST" "'$REMOTE_DIR/obachtctl-linux-arm64' --db='$REMOTE_DB' instance remove --id='$INSTANCE_ID'"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obacht-agent-linux-arm64' -config='$REMOTE_CFG' -once"
LEFT=$(ssh "$PI_HOST" "sudo docker ps -a --filter label=obacht.instance.id=$INSTANCE_ID --format '{{.Names}}'" | wc -l | tr -d ' ')
[ "$LEFT" = "0" ] || die "container still present after removal: $LEFT row(s)"

echo
echo "PASS: core roundtrip on $PI_HOST"
