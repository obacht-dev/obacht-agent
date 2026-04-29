#!/usr/bin/env bash
# S7 telemetry/redaction smoketest.
#
# What we prove:
#   1. The redact package's heuristic correctly classifies common
#      secret-shaped env-var names (unit tests).
#   2. After upserting an instance whose stored config carries
#      `env.DB_PASSWORD=hunter2`, the agent's IPC `GET /v1/admin/
#      instances/{id}` returns `<redacted>` for that key — never the
#      raw value.
#   3. Non-secret env values (PORT, HOST) survive unchanged.
#   4. The response is flagged `sanitized: true`.
#
# We exercise the IPC server directly (not over SSH) and shut it down
# at the end. The real backend telemetry path doesn't expose env at
# all today — this test guards the operator-facing diagnostic surface
# (`obachtctl instance get/list`) which streams up an SSH session.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
WORK="$ROOT/tmp/s7"
SOCKET="$WORK/agent.sock"
CFG="$WORK/agent.yml"
DB="$WORK/agent.db"

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[s7] running redact unit tests..."
go test ./internal/redact/...

echo "[s7] preparing workdir at $WORK..."
rm -rf "$WORK"
mkdir -p "$WORK/caddy/data" "$WORK/caddy/config"
cat >"$CFG" <<EOF
paths:
  stateDb: $DB
  socket: $SOCKET
  caddyData: $WORK/caddy/data
  caddyConfig: $WORK/caddy/config
ingress:
  network: obacht-edge-s7
EOF

echo "[s7] building agent + obachtctl..."
go build -o build/obacht-agent ./cmd/obacht-agent
go build -o build/obachtctl    ./cmd/obachtctl

echo "[s7] starting agent..."
./build/obacht-agent -config="$CFG" -log-level=warn >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!

# wait for socket
for i in $(seq 1 30); do
    [ -S "$SOCKET" ] && break
    sleep 0.1
done
[ -S "$SOCKET" ] || { echo "[s7] FAIL: agent did not open socket"; tail "$WORK/agent.log"; exit 1; }

OBA="./build/obachtctl --socket=$SOCKET"
INST_ID="s7-redact"

cat >"$WORK/cfg.json" <<'EOF'
{
  "env": {
    "DB_PASSWORD": "hunter2",
    "API_TOKEN":   "sekret-abc",
    "PORT":        "8080",
    "HOST":        "localhost",
    "DEBUG":       "1"
  }
}
EOF

echo "[s7] upserting instance with secret-shaped env..."
$OBA instance upsert \
  --id="$INST_ID" \
  --template="redact-test" \
  --runtime="container" \
  --version="1.0.0" \
  --state="stopped" \
  --config-file="$WORK/cfg.json" >/dev/null

echo "[s7] reading back via IPC (list endpoint)..."
RESP=$(curl --silent --unix-socket "$SOCKET" "http://unix/v1/admin/instances")

fail() { echo "[s7] FAIL: $1"; echo "  resp: $RESP"; exit 1; }

# Go's encoding/json HTML-escapes < and > to \u003c \u003e in default
# encoding, so we match the escaped placeholder literal. The check for
# raw secrets below works regardless of escaping.
PLACEHOLDER='\u003credacted\u003e'

echo "$RESP" | grep -qF '"sanitized":true'                       || fail "sanitized flag missing"
echo "$RESP" | grep -qF "\"DB_PASSWORD\":\"$PLACEHOLDER\""       || fail "DB_PASSWORD not redacted"
echo "$RESP" | grep -qF "\"API_TOKEN\":\"$PLACEHOLDER\""         || fail "API_TOKEN not redacted"
echo "$RESP" | grep -qF '"PORT":"8080"'                          || fail "PORT was wrongly modified"
echo "$RESP" | grep -qF '"HOST":"localhost"'                     || fail "HOST was wrongly modified"
if echo "$RESP" | grep -qF 'hunter2'; then
    fail "RAW SECRET LEAKED in response"
fi
if echo "$RESP" | grep -qF 'sekret-abc'; then
    fail "RAW SECRET LEAKED in response"
fi

echo "[s7] OK — env redaction works end-to-end."
