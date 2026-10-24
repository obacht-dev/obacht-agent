#!/usr/bin/env bash
# Tests the obacht-self-update wrapper that install.sh writes to devices.
#
# It extracts the wrapper body verbatim from install.sh, points it at a temp
# directory instead of /opt/obacht-agent, and stubs curl and the agent's
# verify-release. Each case checks whether the downloaded install.sh runs.
#
# The rule under test (security audit 2026-10-22): on an agent that can verify,
# only a verified install.sh runs. Missing, rejected or unverifiable
# signatures all abort.
#
# Run: scripts/test-self-update-wrapper.sh   (no root, no network)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. Extract the wrapper and redirect its fixed paths into $work.
awk "/<<'SELF'\$/{f=1;next} /^SELF\$/{f=0} f" "$here/install.sh" \
  | sed "s#/opt/obacht-agent#$work/opt#g" > "$work/wrapper.sh"
grep -q 'verify-release' "$work/wrapper.sh" || { echo "could not extract wrapper"; exit 1; }

mkdir -p "$work/opt" "$work/bin"

# 2. Stub curl: writes a fake install.sh, and a .minisig unless NO_SIG=1.
cat > "$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
case "$url" in
  *.minisig) [ "${NO_SIG:-0}" = "1" ] && exit 22; echo "sig" > "$out" ;;
  *) printf '#!/usr/bin/env bash\ntouch "%s/RAN"\n' "$WORK" > "$out" ;;
esac
EOF
chmod +x "$work/bin/curl"

# 3. Stub agent: verify-release exits with $VR.
cat > "$work/opt/obacht-agent" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "verify-release" ] && exit "${VR:-0}"
exit 0
EOF
chmod +x "$work/opt/obacht-agent"

fails=0
run_case() { # name marker(0/1) no_sig vr expect(ran|blocked)
  local name="$1" marker="$2" nosig="$3" vr="$4" expect="$5"
  rm -f "$work/RAN"
  if [ "$marker" = "1" ]; then touch "$work/opt/.verify-release-supported"; else rm -f "$work/opt/.verify-release-supported"; fi
  set +e
  PATH="$work/bin:$PATH" WORK="$work" NO_SIG="$nosig" VR="$vr" \
    bash "$work/wrapper.sh" v9.9.9 >/dev/null 2>&1
  set -e
  local got=blocked; [ -f "$work/RAN" ] && got=ran
  if [ "$got" = "$expect" ]; then echo "ok   - $name"; else echo "FAIL - $name (expected $expect, got $got)"; fails=$((fails+1)); fi
}

run_case "verified install.sh runs"                    1 0 0 ran
run_case "missing .minisig is refused"                 1 1 0 blocked
run_case "rejected signature is refused"               1 0 1 blocked
run_case "unverifiable signature (exit 2) is refused"  1 0 2 blocked
run_case "pre-signing agent (no marker) still updates" 0 1 0 ran

# Self-overwrite: install.sh replaces the wrapper while the old wrapper is
# still running it. The old bash must finish its own file and must not read
# into the new one. Uses the real wrapper-writing block from install.sh.
mkdir -p "$work/sbin"
{
  echo 'set -e'
  # the block as install.sh has it, from the line that writes the wrapper to
  # the line that installs it, with paths pointed into $work
  awk '/obacht-self-update/ && /cat >|wrapper_tmp=/ {f=1} f {print} f && /^(mv -f|chmod 0755) .*\/usr\/local\/sbin\/obacht-self-update$/ {exit}' "$here/install.sh"
} | sed "s#/usr/local/sbin#$work/sbin#g" > "$work/write-wrapper.sh"
printf '#!/usr/bin/env bash\nbash "%s"\necho old-wrapper-done\n' "$work/write-wrapper.sh" > "$work/sbin/obacht-self-update"
set +e
out="$(bash "$work/sbin/obacht-self-update" 2>&1)"; rc=$?
set -e
if [ "$rc" -eq 0 ] && [ "$out" = "old-wrapper-done" ] && grep -q 'verify-release' "$work/sbin/obacht-self-update"; then
  echo "ok   - wrapper replaced while running: old process ends cleanly"
else
  echo "FAIL - wrapper replaced while running (rc=$rc, output: $(echo "$out" | head -c 120))"; fails=$((fails+1))
fi

[ "$fails" -eq 0 ] && echo "all wrapper cases passed" || { echo "$fails case(s) failed"; exit 1; }
