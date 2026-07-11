#!/usr/bin/env bash
# sign-release.sh — attach offline minisign signatures to a published
# obacht-agent GitHub release.
#
# Runs on the RELEASE ENGINEER'S WORKSTATION, after CI has built and
# published the release (CI never sees the secret key — that is the whole
# point). It downloads every release artifact, re-checks its sha256,
# minisign-signs it, verifies the signature against the embedded public
# key, and uploads the .minisig back onto the release.
#
# Signed artifacts: every *.tar.gz  AND  install.sh (the wrapper verifies
# install.sh before running it; install.sh verifies the tarball).
#
# Usage:
#   MINISIGN_PASSWORD='…' ./scripts/sign-release.sh v0.4.1
#
# Prereqs: minisign, gh (authenticated), curl, sha256sum/shasum.
# Key:     ~/.config/obacht/obacht-agent-release-1.key  (override with
#          OBACHT_AGENT_RELEASE_KEY). Generate once with:
#   minisign -G -s ~/.config/obacht/obacht-agent-release-1.key \
#            -p ~/.config/obacht/obacht-agent-release-1.pub
#   then paste the .pub into internal/selfupdate/embedded.go and ship an
#   agent release before signing with it.

set -euo pipefail

REPO="${OBACHT_AGENT_REPO:-obacht-dev/obacht-agent}"
KEY="${OBACHT_AGENT_RELEASE_KEY:-$HOME/.config/obacht/obacht-agent-release-1.key}"
TAG="${1:-}"

if [ -z "$TAG" ]; then
  echo "usage: MINISIGN_PASSWORD=… $0 <tag>" >&2
  exit 2
fi
if [ -z "${MINISIGN_PASSWORD:-}" ]; then
  echo "MINISIGN_PASSWORD env var required (secret key passphrase)" >&2
  exit 2
fi
if [ ! -f "$KEY" ]; then
  echo "secret key not found at $KEY (set OBACHT_AGENT_RELEASE_KEY)" >&2
  exit 2
fi
for bin in minisign gh curl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing dependency: $bin" >&2; exit 2; }
done
sha_check() { # portable "sha256sum -c"
  if command -v sha256sum >/dev/null 2>&1; then ( cd "$1" && sha256sum -c "$2" )
  else ( cd "$1" && shasum -a 256 -c "$2" ); fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> downloading release assets for $TAG"
gh release download "$TAG" --repo "$REPO" --dir "$work" --clobber \
  --pattern '*.tar.gz' --pattern '*.tar.gz.sha256' --pattern 'install.sh'

# Collect the artifacts to sign: all tarballs + install.sh. Skip anything
# already carrying a .minisig (idempotent re-runs). Portable to bash 3.2
# (macOS) — no mapfile.
artifacts=()
while IFS= read -r f; do
  [ -n "$f" ] && artifacts+=("$f")
done < <(cd "$work" && ls -1 ./*.tar.gz install.sh 2>/dev/null | sed 's#^\./##' || true)
if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "no signable artifacts found in the release" >&2
  exit 1
fi

PUBKEY_FILE="${OBACHT_AGENT_RELEASE_PUB:-${KEY%.key}.pub}"

uploads=()
for a in "${artifacts[@]}"; do
  # Re-verify the checksum for tarballs before signing (never sign a
  # corrupt download).
  if [ -f "$work/$a.sha256" ]; then
    echo "==> checksum $a"
    sha_check "$work" "$a.sha256"
  fi
  echo "==> signing $a"
  rm -f "$work/$a.minisig"
  # Passphrase on stdin (same pattern as the registry signer). Default sig
  # path is <artifact>.minisig.
  echo "$MINISIGN_PASSWORD" | minisign -S -s "$KEY" -m "$work/$a" \
    -t "obacht-agent release $TAG" >/dev/null
  # Re-verify so a wrong passphrase can't silently produce a useless sig.
  if [ -f "$PUBKEY_FILE" ]; then
    minisign -Vm "$work/$a" -x "$work/$a.minisig" -p "$PUBKEY_FILE" >/dev/null
  fi
  uploads+=("$work/$a.minisig")
done

echo "==> uploading ${#uploads[@]} signatures to $TAG"
gh release upload "$TAG" --repo "$REPO" --clobber "${uploads[@]}"

echo "==> done. signed:"
printf '   %s\n' "${artifacts[@]}"
echo
echo "Verify locally with the embedded key, e.g.:"
echo "  go run ./cmd/obacht-agent verify-release \\"
echo "    --file <(gh release download $TAG -R $REPO -p 'obacht-agent_${TAG}_linux_arm64.tar.gz' -O -) ..."
