#!/usr/bin/env bash
# 05-system-runtime.sh — exercises Phase-5 system runtime + exclusivity locks
# on the real test pi. Validates:
#   - install a system instance (writes a real systemd unit, starts it)
#   - install a second instance claiming the same exclusivity_group → denied
#   - uninstall first → second can now claim the group
#   - uninstall second → unit removed, no leftover lock
#
# We use a no-op `sleep infinity` unit so the test does not depend on display
# / audio hardware. The exclusivity_group is a synthetic name ("test-shared")
# so we do not collide with anything real on the Pi.
#
# Requires: ssh access to PI_HOST, root sudo on the Pi (systemd D-Bus + unit
# writes), local `go` toolchain.
set -euo pipefail

PI_HOST="${PI_HOST:-pi@raspberrypi.local}"
REMOTE_DIR="/tmp/obacht-agent-test"
REMOTE_DB="${REMOTE_DIR}/agent.db"
REMOTE_CFG="${REMOTE_DIR}/agent.yml"
GROUP="test-shared"
UNIT_A="obacht-test-A.service"
UNIT_B="obacht-test-B.service"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s ===\n' "$*"; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

say "1/9 cross-build linux/arm64"
mkdir -p build
GOOS=linux GOARCH=arm64 go build -trimpath -o build/obacht-agent-linux-arm64 ./cmd/obacht-agent
GOOS=linux GOARCH=arm64 go build -trimpath -o build/obachtctl-linux-arm64   ./cmd/obachtctl

say "2/9 push binaries"
ssh "$PI_HOST" "set -e; sudo mkdir -p '$REMOTE_DIR' && sudo chown \$(id -u):\$(id -g) '$REMOTE_DIR'"
scp -q build/obacht-agent-linux-arm64 build/obachtctl-linux-arm64 "$PI_HOST:$REMOTE_DIR/"
ssh "$PI_HOST" "chmod +x '$REMOTE_DIR/obacht-agent-linux-arm64' '$REMOTE_DIR/obachtctl-linux-arm64'"
ssh "$PI_HOST" 'command -v sqlite3 >/dev/null || sudo apt-get install -yq sqlite3'

say "3/9 reset DB and write minimal agent.yml"
ssh "$PI_HOST" "rm -f '$REMOTE_DB'; cat > '$REMOTE_CFG' <<EOF
paths:
  stateDb: $REMOTE_DB
ingress:
  disabled: true
EOF"

# Spec helper: emits a config_json with a sleep-infinity unit + exclusivity_group.
make_spec() {
  local unit="$1"
  cat <<JSON
{"unit_name":"${unit}","unit_template":"[Unit]\nDescription=obacht test ${unit}\n[Service]\nType=simple\nExecStart=/bin/sh -c 'sleep infinity'\nRestart=no\n[Install]\nWantedBy=multi-user.target\n","exclusivity_group":"${GROUP}"}
JSON
}

say "4/9 upsert instance A (system runtime, exclusivity_group=$GROUP)"
ssh "$PI_HOST" "'$REMOTE_DIR/obachtctl-linux-arm64' --db='$REMOTE_DB' instance upsert \
  --id=sys-A --template=test-system --runtime=system --state=installed \
  --version=1.0.0 --config-file=- <<'JSON'
$(make_spec "$UNIT_A")
JSON"

say "5/9 upsert instance B (same exclusivity_group)"
ssh "$PI_HOST" "'$REMOTE_DIR/obachtctl-linux-arm64' --db='$REMOTE_DB' instance upsert \
  --id=sys-B --template=test-system --runtime=system --state=installed \
  --version=1.0.0 --config-file=- <<'JSON'
$(make_spec "$UNIT_B")
JSON"

say "6/9 reconcile once (root, with isolated unit dir for test cleanup)"
ssh "$PI_HOST" "sudo OBACHT_SYSTEMD_UNIT_DIR=/etc/systemd/system OBACHT_SYSTEMD_FILES_DIR=/etc/obacht/system \
  '$REMOTE_DIR/obacht-agent-linux-arm64' --config='$REMOTE_CFG' --once 2>&1" | tail -40 > /tmp/obacht-test-05.log
cat /tmp/obacht-test-05.log

# Expect: A acquired the lock and started; B was denied.
HOLDER=$(ssh "$PI_HOST" "sqlite3 '$REMOTE_DB' \"SELECT instance_id FROM exclusivity_locks WHERE group_name='$GROUP'\"" | tr -d '\r')
[[ "$HOLDER" == "sys-A" ]] || die "expected sys-A to hold lock, got '$HOLDER'"

# Verify A is active, B is not present.
A_STATE=$(ssh "$PI_HOST" "sudo systemctl is-active $UNIT_A" 2>/dev/null || true)
[[ "$A_STATE" == "active" ]] || die "expected $UNIT_A active, got '$A_STATE'"
B_PRESENT=$(ssh "$PI_HOST" "sudo systemctl list-unit-files $UNIT_B 2>/dev/null | grep -c $UNIT_B" || true)
[[ "$B_PRESENT" == "0" ]] || die "$UNIT_B should not have been installed (denied by lock), got count=$B_PRESENT"

say "7/9 uninstall A → reconcile → B should now win"
ssh "$PI_HOST" "'$REMOTE_DIR/obachtctl-linux-arm64' --db='$REMOTE_DB' instance upsert \
  --id=sys-A --template=test-system --runtime=system --state=removed \
  --version=1.0.0 --config-file=- <<'JSON'
$(make_spec "$UNIT_A")
JSON"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obacht-agent-linux-arm64' --config='$REMOTE_CFG' --once 2>&1" | tail -20

HOLDER=$(ssh "$PI_HOST" "sqlite3 '$REMOTE_DB' \"SELECT instance_id FROM exclusivity_locks WHERE group_name='$GROUP'\"" | tr -d '\r')
[[ "$HOLDER" == "sys-B" ]] || die "after A removed, expected sys-B to hold lock, got '$HOLDER'"
B_STATE=$(ssh "$PI_HOST" "sudo systemctl is-active $UNIT_B" 2>/dev/null || true)
[[ "$B_STATE" == "active" ]] || die "expected $UNIT_B active, got '$B_STATE'"
A_PRESENT=$(ssh "$PI_HOST" "sudo systemctl list-unit-files $UNIT_A 2>/dev/null | grep -c $UNIT_A" || true)
[[ "$A_PRESENT" == "0" ]] || die "$UNIT_A should be gone, count=$A_PRESENT"

say "8/9 uninstall B → cleanup"
ssh "$PI_HOST" "'$REMOTE_DIR/obachtctl-linux-arm64' --db='$REMOTE_DB' instance upsert \
  --id=sys-B --template=test-system --runtime=system --state=removed \
  --version=1.0.0 --config-file=- <<'JSON'
$(make_spec "$UNIT_B")
JSON"
ssh "$PI_HOST" "sudo '$REMOTE_DIR/obacht-agent-linux-arm64' --config='$REMOTE_CFG' --once 2>&1" | tail -10

HOLDER=$(ssh "$PI_HOST" "sqlite3 '$REMOTE_DB' \"SELECT instance_id FROM exclusivity_locks WHERE group_name='$GROUP'\"" | tr -d '\r')
[[ -z "$HOLDER" ]] || die "lock should be free, holder='$HOLDER'"

say "9/9 PASS: P5 system runtime + exclusivity locks"
