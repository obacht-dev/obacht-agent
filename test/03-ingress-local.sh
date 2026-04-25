#!/usr/bin/env bash
# 03-ingress-local.sh — smoke-test Phase 3 (Caddy ingress) locally.
#
# Spins up the agent against tmp/agent.yml, exercises domain claim/bind/unclaim
# via obachtctl over IPC, and asserts the generated Caddyfile reflects the SSOT.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    docker rm -f obacht-caddy >/dev/null 2>&1 || true
    docker rm -f obacht-demo  >/dev/null 2>&1 || true
    docker network rm obacht-edge-test >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- prep ---------------------------------------------------------------
pkill -f "build/obacht-agent -config=tmp/agent.yml" 2>/dev/null || true
sleep 1
docker rm -f obacht-caddy >/dev/null 2>&1 || true
docker network rm obacht-edge-test >/dev/null 2>&1 || true

rm -f tmp/agent.db tmp/agent.sock
rm -rf tmp/caddy
mkdir -p tmp/caddy/data tmp/caddy/config

go build -o build/obacht-agent ./cmd/obacht-agent
go build -o build/obachtctl   ./cmd/obachtctl

# --- start agent --------------------------------------------------------
./build/obacht-agent -config=tmp/agent.yml -log-level=info >tmp/agent.log 2>&1 &
AGENT_PID=$!
sleep 1

OBA="./build/obachtctl --socket=tmp/agent.sock"

echo "=== 1/9 health (must be immediate) ==="
$OBA health

echo "=== 2/9 domain claim ==="
$OBA domain claim --domain=test.local.invalid

echo "=== 3/9 wait for caddy pull/start (up to 60s) ==="
for i in $(seq 1 60); do
    if docker ps --filter name=obacht-caddy --format '{{.Names}}' | grep -q obacht-caddy; then
        echo "caddy up after ${i}s"
        break
    fi
    sleep 1
done

if ! docker ps --filter name=obacht-caddy --format '{{.Names}}' | grep -q obacht-caddy; then
    echo "FAIL: caddy container did not come up" >&2
    tail -40 tmp/agent.log >&2
    exit 1
fi

echo "=== 4/9 domain list ==="
$OBA domain list

echo "=== 5/9 register dummy instance, then bind + service ==="
$OBA instance upsert --id=demo --template=ingress-smoke --config-file=- <<'JSON' >/dev/null
{"image":"nginx:alpine"}
JSON
$OBA domain bind --domain=test.local.invalid --instance=demo --service=web
$OBA domain service --instance=demo --service=web --type=docker_dns --target=obacht-demo:80

echo "=== 6/9 ingress reload ==="
$OBA ingress reload
sleep 2

echo "=== 7/9 final Caddyfile (must reverse_proxy obacht-demo:80) ==="
cat tmp/caddy/config/Caddyfile
if ! grep -q "reverse_proxy obacht-demo:80" tmp/caddy/config/Caddyfile; then
    echo "FAIL: Caddyfile missing reverse_proxy line" >&2
    exit 1
fi

echo "=== 8/9 domain list shows bound ==="
$OBA domain list

echo "=== 9/9 unclaim removes from Caddyfile ==="
$OBA domain unclaim --domain=test.local.invalid
sleep 2
cat tmp/caddy/config/Caddyfile
if grep -q "test.local.invalid" tmp/caddy/config/Caddyfile; then
    echo "FAIL: domain still in Caddyfile after unclaim" >&2
    exit 1
fi

echo
echo "PASS: ingress local smoke green"
