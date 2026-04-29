#!/usr/bin/env bash
# S4 minisign signing smoketest.
#
# Verifies that obachtctl template install:
#   1. ACCEPTS a manifest with a valid signature against a key in
#      /etc/obacht/trust.d/ (overridden via OBACHT_TRUST_DIR).
#   2. REJECTS a manifest whose content has been tampered with after
#      signing.
#   3. REJECTS a signature made by an untrusted key.
#   4. REJECTS when --signature-base64 is provided without --manifest-
#      base64 (and vice versa).
#   5. PERMITS templates without any signature flags (S4 rollout
#      compatibility — this is audit-flagged but not blocked).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="/tmp/obacht-s4"
rm -rf "$WORK"; mkdir -p "$WORK/trust"

echo "[s4] building agent + obachtctl..."
( cd "$ROOT" && go build -o "$WORK/obacht-agent" ./cmd/obacht-agent \
              && go build -o "$WORK/obachtctl"   ./cmd/obachtctl )

cat > "$WORK/agent.yml" <<EOF
server:
  url: ""
  deviceId: "dev-s4"
paths:
  stateDb: $WORK/agent.db
  socket:  $WORK/agent.sock
  caddyData: $WORK/caddy/data
  caddyConfig: $WORK/caddy/config
  auditLog: $WORK/audit.log
ingress:
  disabled: true
EOF

echo "[s4] starting agent..."
"$WORK/obacht-agent" --config="$WORK/agent.yml" --log-level=warn \
  > "$WORK/agent.out" 2>&1 &
AGENT=$!
trap 'kill $AGENT 2>/dev/null || true' EXIT
sleep 1

# --- Generate two keypairs (trusted + untrusted) and sign a manifest ----
echo "[s4] generating keypairs + signing manifest via test helper..."
go run "$ROOT/test/s4-sign-helper.go" "$WORK"

TRUSTED_PUB="$WORK/trusted.pub"
UNTRUSTED_SIG_B64="$(cat $WORK/untrusted-sig.b64)"
TRUSTED_SIG_B64="$(cat $WORK/trusted-sig.b64)"
MANIFEST_B64="$(cat $WORK/manifest.b64)"
TAMPERED_MANIFEST_B64="$(cat $WORK/tampered-manifest.b64)"

cp "$TRUSTED_PUB" "$WORK/trust/registry.pub"

OBACHTCTL="$WORK/obachtctl"
SOCK="--socket=$WORK/agent.sock"
export OBACHT_TRUST_DIR="$WORK/trust"

# --- 1. Valid signature → success ----------------------------------------
echo "[s4] case 1: valid signature accepted"
$OBACHTCTL $SOCK template install --id static-site --instance s4-ok \
  --json --version 1.0.0 \
  --config-json '{"image":"caddy:2-alpine"}' \
  --manifest-base64 "$MANIFEST_B64" \
  --signature-base64 "$TRUSTED_SIG_B64" \
  | grep -q '"ok":true'
echo "[s4]   ok"

# --- 2. Tampered manifest → reject ---------------------------------------
echo "[s4] case 2: tampered manifest rejected"
if $OBACHTCTL $SOCK template install --id static-site --instance s4-tamper \
  --json --version 1.0.0 \
  --config-json '{"image":"caddy:2-alpine"}' \
  --manifest-base64 "$TAMPERED_MANIFEST_B64" \
  --signature-base64 "$TRUSTED_SIG_B64" 2> "$WORK/err2.txt"; then
  echo "[s4]   FAIL: tampered manifest was accepted"
  exit 1
fi
grep -q "signature rejected" "$WORK/err2.txt"
echo "[s4]   ok ($(cat $WORK/err2.txt))"

# --- 3. Untrusted key → reject -------------------------------------------
echo "[s4] case 3: untrusted-key signature rejected"
if $OBACHTCTL $SOCK template install --id static-site --instance s4-untrusted \
  --json --version 1.0.0 \
  --config-json '{"image":"caddy:2-alpine"}' \
  --manifest-base64 "$MANIFEST_B64" \
  --signature-base64 "$UNTRUSTED_SIG_B64" 2> "$WORK/err3.txt"; then
  echo "[s4]   FAIL: untrusted key was accepted"
  exit 1
fi
grep -q "signature rejected" "$WORK/err3.txt"
echo "[s4]   ok ($(cat $WORK/err3.txt))"

# --- 4. Mismatched flag pair → reject ------------------------------------
echo "[s4] case 4: --signature without --manifest rejected"
if $OBACHTCTL $SOCK template install --id static-site --instance s4-half \
  --json --version 1.0.0 \
  --config-json '{"image":"caddy:2-alpine"}' \
  --signature-base64 "$TRUSTED_SIG_B64" 2> "$WORK/err4.txt"; then
  echo "[s4]   FAIL: half-pair was accepted"
  exit 1
fi
grep -q "must be used together" "$WORK/err4.txt"
echo "[s4]   ok"

# --- 5. No signature → permitted (rollout compat) ------------------------
echo "[s4] case 5: unsigned install permitted (audit-flagged)"
$OBACHTCTL $SOCK template install --id static-site --instance s4-unsigned \
  --json --version 1.0.0 \
  --config-json '{"image":"caddy:2-alpine"}' \
  | grep -q '"ok":true'
echo "[s4]   ok"

# --- audit log inspection -------------------------------------------------
echo "[s4] audit tail:"
$OBACHTCTL $SOCK audit tail --n 8

echo "[s4] PASS"
