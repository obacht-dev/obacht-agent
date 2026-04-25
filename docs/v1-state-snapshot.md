# v1 State Snapshot — `meinNeuerPi`

> Captured 2026-04-25 from `pi@raspberrypi.local` via SSH/WireGuard.
> Used as input for the v2 hard-cut migration plan.

## Host

- **OS**: Debian GNU/Linux 13 (trixie), aarch64
- **Kernel**: 6.12.62+rpt-rpi-v8
- **Hardware**: Raspberry Pi (aarch64)

## v1 Agent

- **Path**: `/opt/obacht/`
  - `agent.py` (33 KB), `template_manager.py` (28 KB), `system_info.py` (4.7 KB)
  - `venv/` (Python virtualenv with deps)
  - `templates/selfhost-website-simple/` (only installed template)
  - `.installed` marker
- **Systemd unit**: `obacht-agent.service` (active, running since 2026-04-12, enabled)
  - Main PID runs `/opt/obacht/venv/bin/python3 /opt/obacht/agent.py`
  - Spawns child `/opt/obacht/templates/selfhost-website-simple/handler.py`
- **Config**: `/etc/obacht/agent.yml` (mode 0600, root only)
- **State file**: `/var/lib/obacht/agent/state.json`:
  ```json
  {
    "installedTemplates": {
      "selfhost-website-simple": {
        "version": "1.0.23",
        "config": {},
        "installedAt": 69.842681324
      }
    }
  }
  ```

## Installed templates

| Template                      | Version | Status                          |
|-------------------------------|---------|---------------------------------|
| `selfhost-website-simple`     | 1.0.23  | Running, no domain configured   |

`selfhost-website-simple` reports state every ~10s with empty `domain`/`ssl_email`
— never bound to a real domain. **No user-visible site is live**, so the migration
is risk-free.

## Networking

- **WireGuard `wg0`** up. Single peer = obacht-proxy (`188.245.211.20:51820`,
  AllowedIPs `10.137.0.1/32`). Latest handshake recent. Tunnel healthy.
- **Listening ports**:
  - 22 (sshd)
  - 80 (nginx)
  - 443 (nginx)
  - 5900 (wayvnc)
  - 631 (cupsd, localhost)
  - 111 (rpcbind)
- **nginx** runs on host as `nginx.service` (Debian package), serving 80/443
  for `selfhost-website-simple`. **Will conflict with v2 Caddy container**.
- **Docker**: NOT installed. v2 bootstrap must `apt install docker.io` (or
  use the official docker.com convenience script).

## TLS

- `/etc/letsencrypt/live/` — root-owned, contents not enumerable as `pi` user;
  given `selfhost-website-simple` has no domain configured, we expect no
  active certs. To verify before wipe: `sudo ls /etc/letsencrypt/live`.

## Migration implications for v2 hard-cut

1. Stop & disable `obacht-agent.service` (v1 systemd unit).
2. Stop & disable `nginx.service` (frees ports 80/443 for Caddy container).
3. `apt install -y docker.io` (Debian 13 ships it, simpler than docker.com script).
4. `rm -rf /opt/obacht /etc/obacht /var/lib/obacht/agent` (after confirming
   no precious data — confirmed by snapshot above: only `selfhost` template
   without configured domain).
5. Run v2 bootstrap, point at existing device-id (so backend keeps history).
6. WireGuard config (`/etc/wireguard/wg0.conf`) **stays** — same peer, same IP.

## Key paths v2 will use

| Purpose          | Path (Linux)                           |
|------------------|----------------------------------------|
| Daemon binary    | `/usr/local/bin/obacht-agent`          |
| CLI binary       | `/usr/local/bin/obachtctl`             |
| Config           | `/etc/obacht/agent.yml`                |
| SQLite SSOT      | `/var/lib/obacht/agent.db`             |
| Caddy data/certs | `/var/lib/obacht/caddy/{data,config}`  |
| IPC socket       | `/run/obacht/agent.sock`               |
| Systemd unit     | `/etc/systemd/system/obacht-agent.service` |
