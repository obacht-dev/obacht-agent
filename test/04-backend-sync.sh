#!/usr/bin/env bash
# test/04-backend-sync.sh — Phase 4 backend sync smoke against prod.
#
# What it asserts:
#   1. Agent connects via Socket.IO to api.eu.obacht.dev/ws/devices.
#   2. `agent:register` causes devices.agent_v2 = true and devices.agent_version
#      to populate (verified against obacht-db).
#   3. The 30s observed-state push causes devices.last_observed_state_at to
#      advance (verified against obacht-db).
#
# Pre-reqs:
#   - ssh alias `pi` -> pi@raspberrypi.local with NOPASSWD sudo
#   - ssh alias `obacht-db` -> obacht-db host with sudo + docker access
#   - existing /etc/obacht/agent.yml on pi with valid server.authToken/deviceId
#     (we read deviceId from there to verify in DB)
#
# This script is intentionally non-destructive to the existing v1 install:
#   - we copy v2 binary to /usr/local/bin/obacht-agent-v2 (does NOT replace v1)
#   - we use a separate state DB at /var/lib/obacht/agent-v2.db
#   - we use a separate socket at /run/obacht/agent-v2.sock
#   - v1 obacht-agent.service is stopped while we run, then re-started at end

set -euo pipefail

PI="${PI:-pi@raspberrypi.local}"
DB="${DB:-obacht-db}"
DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
DB_USER="${DB_USER:-supabase_admin}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bin_local="bin/obacht-agent-linux-arm64"
bin_remote="/usr/local/bin/obacht-agent-v2"
ctl_remote="/usr/local/bin/obachtctl-v2"
sock_remote="/run/obacht/agent-v2.sock"
state_remote="/var/lib/obacht/agent-v2.db"
yml_remote="/etc/obacht/agent-v2.yml"
log_remote="/tmp/obacht-agent-v2.log"

agent_version="0.2.0-test"
echo
echo "=== 1/8 cross-build linux/arm64 (version=${agent_version}) ==="
mkdir -p bin
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.agentVersion=${agent_version}" \
  -o "${bin_local}" ./cmd/obacht-agent
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o bin/obachtctl-linux-arm64 ./cmd/obachtctl

echo
echo "=== 2/8 ship binaries to pi ==="
scp -q "${bin_local}" "${PI}:/tmp/obacht-agent-v2"
scp -q bin/obachtctl-linux-arm64 "${PI}:/tmp/obachtctl-v2"
ssh "${PI}" "sudo install -m 0755 /tmp/obacht-agent-v2 ${bin_remote} && sudo install -m 0755 /tmp/obachtctl-v2 ${ctl_remote}"

echo
echo "=== 3/8 read existing v1 agent.yml to crib server creds ==="
read -r DEVICE_ID AUTH_TOKEN SERVER_URL < <(
  ssh "${PI}" "sudo awk '
    /^server:/ {in_s=1; next}
    in_s && /^[^[:space:]]/ {in_s=0}
    in_s && /authToken:/ {gsub(\"authToken: *\",\"\"); a=\$0}
    in_s && /deviceId:/  {gsub(\"deviceId: *\",\"\");  d=\$0}
    in_s && /url:/       {gsub(\"url: *\",\"\");       u=\$0}
    END {print d, a, u}
  ' /etc/obacht/agent.yml"
)
echo "device_id=${DEVICE_ID}"
echo "server   =${SERVER_URL}"
echo "token    =${AUTH_TOKEN:0:24}…(redacted)"

echo
echo "=== 4/8 write v2-only agent.yml (separate state, socket, ingress disabled) ==="
ssh "${PI}" "sudo tee ${yml_remote} >/dev/null" <<EOF
server:
  url: ${SERVER_URL}
  deviceId: ${DEVICE_ID}
  authToken: ${AUTH_TOKEN}
registry:
  url: https://registry.eu.obacht.dev
paths:
  stateDb: ${state_remote}
  socket: ${sock_remote}
ingress:
  disabled: true
EOF

echo
echo "=== 5/8 stop legacy v1 agent (so it doesn't fight us on the same socket name) ==="
ssh "${PI}" "sudo systemctl stop obacht-agent 2>/dev/null || true"
# kill any stray test agent
ssh "${PI}" "for pid in \$(ps -eo pid,comm | awk '\$2==\"obacht-agent-v2\" {print \$1}'); do sudo kill \$pid; done; true"

echo
echo "=== 6/8 baseline DB snapshot ==="
baseline_obs=$(ssh "${DB}" "sudo docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d postgres -tAc \
  \"select coalesce(extract(epoch from last_observed_state_at)::int, 0) from devices where id='${DEVICE_ID}'\"")
baseline_v2=$(ssh "${DB}" "sudo docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d postgres -tAc \
  \"select agent_v2 from devices where id='${DEVICE_ID}'\"")
echo "baseline last_observed_state_at = ${baseline_obs}"
echo "baseline agent_v2               = ${baseline_v2}"

echo
echo "=== 7/8 start v2 agent on pi (60s, then kill) ==="
ssh "${PI}" "sudo nohup ${bin_remote} -config ${yml_remote} -log-level debug > ${log_remote} 2>&1 &" || true
# Wait for connect → register → first observed push (which the syncer fires
# immediately on connect; then again every 30s).
echo "waiting up to 60s for backend to record register + observed state…"

ok_register=0
ok_observed=0
for i in $(seq 1 60); do
  sleep 1
  if [[ ${ok_register} -eq 0 ]]; then
    cur_v2=$(ssh "${DB}" "sudo docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d postgres -tAc \
      \"select agent_v2 from devices where id='${DEVICE_ID}'\"" 2>/dev/null || echo "")
    cur_ver=$(ssh "${DB}" "sudo docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d postgres -tAc \
      \"select coalesce(agent_version,'') from devices where id='${DEVICE_ID}'\"" 2>/dev/null || echo "")
    if [[ "${cur_v2}" == "t" && "${cur_ver}" == "${agent_version}" ]]; then
      ok_register=1
      echo "  [${i}s] register OK (agent_v2=t, agent_version=${cur_ver})"
    fi
  fi
  if [[ ${ok_observed} -eq 0 ]]; then
    cur_obs=$(ssh "${DB}" "sudo docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d postgres -tAc \
      \"select coalesce(extract(epoch from last_observed_state_at)::int, 0) from devices where id='${DEVICE_ID}'\"" 2>/dev/null || echo "0")
    if [[ "${cur_obs}" -gt "${baseline_obs}" ]]; then
      ok_observed=1
      echo "  [${i}s] observed_state OK (last_observed_state_at advanced ${baseline_obs} → ${cur_obs})"
    fi
  fi
  if [[ ${ok_register} -eq 1 && ${ok_observed} -eq 1 ]]; then
    break
  fi
done

echo
echo "=== 8/8 stop agent + restart v1 ==="
ssh "${PI}" "for pid in \$(ps -eo pid,comm | awk '\$2==\"obacht-agent-v2\" {print \$1}'); do sudo kill \$pid; done; true"
sleep 2
ssh "${PI}" "sudo systemctl start obacht-agent 2>/dev/null || true"

echo
echo "=== agent log tail (for debugging) ==="
ssh "${PI}" "sudo tail -60 ${log_remote}" || true

if [[ ${ok_register} -ne 1 || ${ok_observed} -ne 1 ]]; then
  echo
  echo "FAIL: register=${ok_register} observed=${ok_observed} (expected both 1)"
  exit 1
fi

echo
echo "PASS: backend sync smoke (device=${DEVICE_ID})"
