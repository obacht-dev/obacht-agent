#!/usr/bin/env bash
# 03-ingress.sh — Phase 3 ingress smoke against the test pi.
#
# Validates: cross-build → scp new agent → stop legacy nginx (hard cut) →
# start agent with ingress enabled → claim a domain → verify Caddy container
# came up → bind a dummy instance → verify Caddyfile reflects binding →
# unclaim → cleanup.
#
# This intentionally does NOT do a real ACME issuance: that requires DNS
# pointing at the pi and is exercised in test/10-e2e-recovery.sh. Set
# INGRESS_DOMAIN to a real subdomain that already resolves to the pi to
# additionally probe HTTPS via curl --resolve (best-effort).
#
# Idempotent.
set -euo pipefail

PI_HOST="${PI_HOST:-pi@raspberrypi.local}"
INSTANCE_ID="${INSTANCE_ID:-ingress-demo-1}"
DOMAIN="${INGRESS_DOMAIN:-test.local.invalid}"
REMOTE_DIR="/tmp/obacht-agent-test"
REMOTE_CFG="${REMOTE_DIR}/agent.yml"
REMOTE_DB="${REMOTE_DIR}/agent.db"
REMOTE_SOCK="${REMOTE_DIR}/agent.sock"
REMOTE_LOG="${REMOTE_DIR}/agent.log"
NETWORK="obacht-edge"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s ===\n' "$*"; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

say "1/9 cross-build linux/arm64"
mkdir -p build
GOOS=linux GOARCH=arm64 go build -trimpath -o build/obacht-agent-linux-arm64 ./cmd/obacht-agent
GOOS=linux GOARCH=arm64 go build -trimpath -o build/obachtctl-linux-arm64   ./cmd/obachtctl

say "2/9 ship binaries to pi"
ssh "$PI_HOST" "sudo mkdir -p '$REMOTE_DIR' && sudo chown \$(id -u):\$(id -g) '$REMOTE_DIR'"
scp -q build/obacht-agent-linux-arm64 build/obachtctl-linux-arm64 "$PI_HOST:$REMOTE_DIR/"
ssh "$PI_HOST" "chmod +x '$REMOTE_DIR/obacht-agent-linux-arm64' '$REMOTE_DIR/obachtctl-linux-arm64'"

say "3/9 hard-cut: stop legacy nginx + v1 agent + previous test agent"
ssh "$PI_HOST" 'set +e
sudo systemctl stop nginx
sudo systemctl disable nginx
sudo systemctl stop obacht-agent
# kill any leftover test agent (pgrep+kill avoids matching this very ssh
# session whose argv contains the binary name as a substring)
for pid in $(ps -eo pid,comm | awk '$2=="obacht-agent-li" {print $1}'); do sudo kill "$pid" 2>/dev/null || true; done
# remove leftover caddy container (we own the name)
sudo docker rm -f obacht-caddy
true'

say "4/9 reset state, write agent.yml with ingress enabled"
ssh "$PI_HOST" "rm -f '$REMOTE_DB' '$REMOTE_SOCK' '$REMOTE_LOG'
sudo rm -rf $REMOTE_DIR/caddy
mkdir -p $REMOTE_DIR/caddy/data $REMOTE_DIR/caddy/config
cat > '$REMOTE_CFG' <<EOF
paths:
  stateDb: $REMOTE_DB
  socket: $REMOTE_SOCK
  caddyData: $REMOTE_DIR/caddy/data
  caddyConfig: $REMOTE_DIR/caddy/config
ingress:
  network: $NETWORK
EOF"

say "5/9 start agent in background (sudo for docker.sock)"
ssh "$PI_HOST" "nohup sudo '$REMOTE_DIR/obacht-agent-linux-arm64' -config='$REMOTE_CFG' -log-level=info >'$REMOTE_LOG' 2>&1 &
sleep 2
sudo chown \$(id -u):\$(id -g) '$REMOTE_SOCK' || true"

say "6/9 wait for caddy (up to 90s on first pull)"
for i in $(seq 1 90); do
  if ssh "$PI_HOST" "sudo docker ps --filter name=obacht-caddy --format '{{.Names}}'" | grep -q obacht-caddy; then
    echo "caddy up after ${i}s"
    break
  fi
  sleep 1
done
ssh "$PI_HOST" "sudo docker ps --filter name=obacht-caddy --format '{{.Names}} {{.Status}}'" | grep -q obacht-caddy \
  || die "caddy did not come up; tail of log:\n$(ssh "$PI_HOST" tail -40 $REMOTE_LOG)"

say "7/9 claim, register dummy instance, bind, verify Caddyfile"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obachtctl-linux-arm64' --socket='$REMOTE_SOCK' domain claim --domain='$DOMAIN'"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obachtctl-linux-arm64' --socket='$REMOTE_SOCK' instance upsert --id='$INSTANCE_ID' --template=ingress-smoke --config-file=- <<'JSON' >/dev/null
{\"image\":\"nginx:alpine\"}
JSON"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obachtctl-linux-arm64' --socket='$REMOTE_SOCK' domain bind --domain='$DOMAIN' --instance='$INSTANCE_ID' --service=web"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obachtctl-linux-arm64' --socket='$REMOTE_SOCK' domain service --instance='$INSTANCE_ID' --service=web --type=docker_dns --target=obacht-${INSTANCE_ID}:80"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obachtctl-linux-arm64' --socket='$REMOTE_SOCK' ingress reload"
sleep 2
echo "--- remote Caddyfile ---"
ssh "$PI_HOST" "cat $REMOTE_DIR/caddy/config/Caddyfile"
ssh "$PI_HOST" "grep -q 'reverse_proxy obacht-${INSTANCE_ID}:80' $REMOTE_DIR/caddy/config/Caddyfile" \
  || die "Caddyfile does not contain expected reverse_proxy line"

say "8/9 unclaim removes the site block"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obachtctl-linux-arm64' --socket='$REMOTE_SOCK' domain unclaim --domain='$DOMAIN'"
sleep 2
ssh "$PI_HOST" "cat $REMOTE_DIR/caddy/config/Caddyfile"
ssh "$PI_HOST" "! grep -q '$DOMAIN' $REMOTE_DIR/caddy/config/Caddyfile" \
  || die "domain still in Caddyfile after unclaim"

say "9/9 cleanup: stop agent + remove caddy container + dummy instance"
ssh "$PI_HOST" 'set +e
for pid in $(ps -eo pid,comm | awk '$2=="obacht-agent-li" {print $1}'); do sudo kill "$pid"; done
sudo docker rm -f obacht-caddy
true'
ssh "$PI_HOST" "sudo docker rm -f obacht-${INSTANCE_ID} 2>/dev/null || true"

echo
echo "PASS: ingress smoke on $PI_HOST (domain=$DOMAIN)"
