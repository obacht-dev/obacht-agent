#!/usr/bin/env bash
# obacht-agent uninstaller.
#
# Removes what install.sh (and, with flags, the platform bootstrap script)
# put on the machine, so the same box can be installed again from scratch.
# Mirrors install.sh section by section. Pure ASCII on purpose (see install.sh).
#
# Usage:
#   sudo ./uninstall.sh --dry-run                 # show what would be removed
#   sudo ./uninstall.sh --yes                     # agent, instances, state
#   sudo ./uninstall.sh --yes --purge-images --remove-wireguard --remove-user
#
# Flags:
#   --yes               required to actually delete anything
#   --dry-run           print the plan, change nothing
#   --purge-images      also delete images used by obacht-managed containers
#   --remove-wireguard  stop wg-quick@wg0 and delete /etc/wireguard/wg0.conf
#                       (only when it is the obacht tunnel: Address in 10.137.0.0/16)
#   --remove-user       delete the obacht and obacht-kiosk users and the admin
#                       sudoers grant (010_obacht-nopasswd). Never use this when
#                       obacht is your login user.
#   --keep-docker-config  leave /etc/docker/daemon.json even if install.sh wrote it
#
# What survives on purpose: Docker itself, SSH authorized_keys lines, the
# device row in the obacht backend (delete the device in the web app).

set -euo pipefail

DRY=0; YES=0; PURGE_IMAGES=0; RM_WG=0; RM_USER=0; KEEP_DOCKER_CFG=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    --purge-images) PURGE_IMAGES=1 ;;
    --remove-wireguard) RM_WG=1 ;;
    --remove-user) RM_USER=1 ;;
    --keep-docker-config) KEEP_DOCKER_CFG=1 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" != "0" ]; then echo "run as root (sudo)" >&2; exit 1; fi
if [ "$DRY" = "0" ] && [ "$YES" = "0" ]; then
  echo "refusing to delete without --yes (or use --dry-run)" >&2; exit 2
fi

run() {
  if [ "$DRY" = "1" ]; then echo "  would: $*"; else echo "  $*"; "$@" || true; fi
}
rm_path() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then run rm -rf -- "$p"; fi
  done
}
have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

echo "==> stopping the agent"
if systemctl list-unit-files obacht-agent.service >/dev/null 2>&1; then
  run systemctl disable --now obacht-agent.service
fi

echo "==> system-runtime units (obacht-svc-*, obacht-kiosk)"
for u in /etc/systemd/system/obacht-svc-*.service /etc/systemd/system/obacht-kiosk.service; do
  [ -e "$u" ] || continue
  run systemctl disable --now "$(basename "$u")"
  rm_path "$u"
done
rm_path /etc/systemd/system/obacht-agent.service

if have_docker; then
  echo "==> containers, compose projects, volumes, network"
  IMAGES=""
  ids="$(docker ps -aq --filter label=obacht.managed=1; docker ps -aq --filter name='^obacht-caddy$'; docker ps -aq --filter label=com.docker.compose.project | while read -r c; do
    p="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$c" 2>/dev/null || true)"
    case "$p" in obacht-*) echo "$c" ;; esac
  done)"
  ids="$(printf '%s\n' "$ids" | sort -u | sed '/^$/d')"
  if [ -n "$ids" ]; then
    IMAGES="$(docker inspect --format '{{.Image}}' $ids 2>/dev/null | sort -u || true)"
    run docker rm -f -v $ids
  fi
  vols="$(docker volume ls -q | while read -r v; do
    p="$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$v" 2>/dev/null || true)"
    case "$p" in obacht-*) echo "$v" ;; esac
  done)"
  if [ -n "$vols" ]; then run docker volume rm $vols; fi
  if docker network inspect obacht-edge >/dev/null 2>&1; then run docker network rm obacht-edge; fi
  if [ "$PURGE_IMAGES" = "1" ] && [ -n "$IMAGES" ]; then
    echo "==> images"
    run docker rmi $IMAGES
  fi
else
  echo "==> docker not reachable, skipping containers"
fi

echo "==> files"
rm_path /opt/obacht-agent /usr/local/bin/obachtctl /usr/local/sbin/obacht-power-toggle /usr/local/sbin/obacht-self-update
rm_path /etc/sudoers.d/obacht-bootstrap /etc/sudoers.d/obacht-power /etc/sudoers.d/obacht
rm_path /etc/obacht /var/lib/obacht /var/log/obacht /opt/obacht /var/lib/obacht-power /run/obacht

if [ "$KEEP_DOCKER_CFG" = "0" ] && [ -f /etc/docker/daemon.json ]; then
  # Only the exact file install.sh writes; a hand-made daemon.json stays.
  if [ "$(tr -d ' \n' < /etc/docker/daemon.json)" = '{"max-concurrent-downloads":2}' ]; then
    rm_path /etc/docker/daemon.json
    echo "  (docker keeps the setting until its next restart)"
  fi
fi

if [ "$RM_WG" = "1" ] && [ -f /etc/wireguard/wg0.conf ]; then
  echo "==> wireguard"
  if grep -qE '^Address *= *10\.137\.' /etc/wireguard/wg0.conf; then
    run systemctl disable --now wg-quick@wg0
    rm_path /etc/wireguard/wg0.conf /etc/wireguard/privatekey /etc/wireguard/publickey
  else
    echo "  /etc/wireguard/wg0.conf is not the obacht tunnel, left alone"
  fi
fi

if [ "$RM_USER" = "1" ]; then
  echo "==> users"
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" = "obacht" ]; then
    echo "  you are logged in as obacht; not deleting the user you are using" >&2
  else
    for u in obacht-kiosk obacht; do
      if id "$u" >/dev/null 2>&1; then run userdel -r "$u"; fi
    done
    rm_path /etc/sudoers.d/010_obacht-nopasswd
  fi
fi

run systemctl daemon-reload
if [ "$DRY" = "1" ]; then echo "==> dry run, nothing changed"; else echo "==> obacht agent removed"; fi
