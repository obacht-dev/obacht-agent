#!/usr/bin/env bash
# S5 restricted-mode + power-mode toggle smoketest.
#
# What we prove:
#   1. obacht-power-toggle binary builds and is callable
#   2. A signed manifest with spec.minSudoLevel=power is REJECTED while
#      power_mode is locked
#   3. `obachtctl system unlock-power --yes --skip-sudo` flips
#      power_mode=true via IPC
#   4. The same install now SUCCEEDS
#   5. `obachtctl system lock-power --yes --skip-sudo` flips it back
#   6. The install is REJECTED again
#
# We pass --skip-sudo to unlock/lock because this test runs unprivileged
# on macOS dev boxes — the real binary requires sudo + a sudoers entry
# that install.sh sets up only on Linux Pi hosts. The sudo path itself
# is exercised in CI on a real Pi (not part of this local smoketest).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="/tmp/obacht-s5"
rm -rf "$WORK"; mkdir -p "$WORK/trust"

echo "[s5] building agent + obachtctl + obacht-power-toggle..."
( cd "$ROOT" && \
    go build -o "$WORK/obacht-agent"        ./cmd/obacht-agent && \
    go build -o "$WORK/obachtctl"           ./cmd/obachtctl && \
    go build -o "$WORK/obacht-power-toggle" ./cmd/obacht-power-toggle )

# Sanity: the toggle binary refuses to do anything without root.
echo "[s5] obacht-power-toggle refuses unprivileged enable..."
if "$WORK/obacht-power-toggle" enable 2> "$WORK/toggle-err.txt"; then
  echo "[s5]   FAIL: toggle accepted unprivileged enable"
  exit 1
fi
grep -q "must run as root" "$WORK/toggle-err.txt"
echo "[s5]   ok"

cat > "$WORK/agent.yml" <<EOF
server:
  url: ""
  deviceId: "dev-s5"
paths:
  stateDb: $WORK/agent.db
  socket:  $WORK/agent.sock
  caddyData: $WORK/caddy/data
  caddyConfig: $WORK/caddy/config
  auditLog: $WORK/audit.log
ingress:
  disabled: true
EOF

echo "[s5] starting agent..."
"$WORK/obacht-agent" --config="$WORK/agent.yml" --log-level=warn \
  > "$WORK/agent.out" 2>&1 &
AGENT=$!
trap 'kill $AGENT 2>/dev/null || true' EXIT
sleep 1

# Generate keypair + sign a manifest that opts into spec.minSudoLevel=power.
echo "[s5] minting keypair + signing power-level manifest..."
cat > "$WORK/sign-helper.go" <<'EOF'
//go:build ignore
package main
import (
  "crypto/rand"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "os"
  "aead.dev/minisign"
)
func main() {
  pub, priv, _ := minisign.GenerateKey(rand.Reader)
  pubBytes, _ := pub.MarshalText()
  os.WriteFile(os.Args[1]+"/trust/registry.pub", pubBytes, 0o644)

  manifest := map[string]any{
    "apiVersion": "obacht.dev/v2",
    "kind": "Template",
    "metadata": map[string]any{
      "name": "power-tpl", "displayName": "Power", "version": "1.0.0",
    },
    "spec": map[string]any{
      "minSudoLevel": "power",
      "runtime": map[string]any{"type":"container","container":map[string]any{"image":"nginx:alpine"}},
    },
  }
  manifestBytes, _ := json.Marshal(manifest)
  sig := minisign.Sign(priv, manifestBytes)
  os.WriteFile(os.Args[1]+"/manifest.b64",
    []byte(base64.StdEncoding.EncodeToString(manifestBytes)), 0o644)
  os.WriteFile(os.Args[1]+"/sig.b64",
    []byte(base64.StdEncoding.EncodeToString(sig)), 0o644)
  fmt.Println("done")
}
EOF
( cd "$ROOT" && go run "$WORK/sign-helper.go" "$WORK" )

MANIFEST_B64="$(cat $WORK/manifest.b64)"
SIG_B64="$(cat $WORK/sig.b64)"
OBACHTCTL="$WORK/obachtctl"
SOCK="--socket=$WORK/agent.sock"
export OBACHT_TRUST_DIR="$WORK/trust"

# --- 1. power-level install REJECTED while locked -----------------------
echo "[s5] case 1: power-level install rejected while power_mode is locked"
if $OBACHTCTL $SOCK template install --id power-tpl --instance s5-locked \
  --json --version 1.0.0 \
  --config-json '{"image":"nginx:alpine"}' \
  --manifest-base64 "$MANIFEST_B64" \
  --signature-base64 "$SIG_B64" 2> "$WORK/err1.txt"; then
  echo "[s5]   FAIL: install was accepted while locked"
  cat "$WORK/err1.txt"
  exit 1
fi
grep -q "power mode" "$WORK/err1.txt" || { echo "[s5]   FAIL: wrong error: $(cat $WORK/err1.txt)"; exit 1; }
echo "[s5]   ok ($(cat $WORK/err1.txt))"

# --- 2. unlock-power --yes --skip-sudo flips the IPC setting ------------
echo "[s5] case 2: unlock-power --yes --skip-sudo enables power_mode"
$OBACHTCTL $SOCK system unlock-power --yes --skip-sudo --json \
  | grep -q '"ok":true' || { echo "[s5]   FAIL: unlock did not return ok"; exit 1; }
echo "[s5]   ok"

# Verify via system status
$OBACHTCTL $SOCK system status --json > "$WORK/status.json"
grep -q '"power_mode":true' "$WORK/status.json" || \
  { echo "[s5]   FAIL: power_mode not true in status: $(cat $WORK/status.json)"; exit 1; }

# --- 3. install now SUCCEEDS --------------------------------------------
echo "[s5] case 3: power-level install accepted while unlocked"
$OBACHTCTL $SOCK template install --id power-tpl --instance s5-ok \
  --json --version 1.0.0 \
  --config-json '{"image":"nginx:alpine"}' \
  --manifest-base64 "$MANIFEST_B64" \
  --signature-base64 "$SIG_B64" \
  | grep -q '"ok":true' || { echo "[s5]   FAIL: install rejected while unlocked"; exit 1; }
echo "[s5]   ok"

# --- 4. lock-power flips it back ----------------------------------------
echo "[s5] case 4: lock-power --yes --skip-sudo disables power_mode"
$OBACHTCTL $SOCK system lock-power --yes --skip-sudo --json \
  | grep -q '"ok":true' || { echo "[s5]   FAIL: lock did not return ok"; exit 1; }

$OBACHTCTL $SOCK system status --json > "$WORK/status2.json"
grep -q '"power_mode":false' "$WORK/status2.json" || \
  { echo "[s5]   FAIL: power_mode not false in status: $(cat $WORK/status2.json)"; exit 1; }
echo "[s5]   ok"

# --- 5. install rejected again ------------------------------------------
echo "[s5] case 5: power-level install rejected again after lock"
if $OBACHTCTL $SOCK template install --id power-tpl --instance s5-relocked \
  --json --version 1.0.0 \
  --config-json '{"image":"nginx:alpine"}' \
  --manifest-base64 "$MANIFEST_B64" \
  --signature-base64 "$SIG_B64" 2> "$WORK/err5.txt"; then
  echo "[s5]   FAIL: install accepted while re-locked"
  exit 1
fi
grep -q "power mode" "$WORK/err5.txt"
echo "[s5]   ok"

echo "[s5] audit tail:"
$OBACHTCTL $SOCK audit tail --n 8

echo "[s5] PASS"
