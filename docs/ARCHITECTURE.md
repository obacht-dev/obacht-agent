# obacht-agent v2 — Architecture

> Living document. Source of truth for design decisions. Update with every
> non-trivial change.

## Leitprinzipien

1. **Agent ist SSOT pro Device** — alles was installiert ist, liegt in
   `/var/lib/obacht/agent.db` (SQLite). Reboot-/Crash-sicher, unabhängig vom
   Backend.
2. **Ingress ist Agent-owned** — Templates dürfen niemals selbst Domains
   claimen, Zertifikate ausstellen oder Reverse-Proxies konfigurieren. Caddy
   läuft als Docker-Container und wird ausschließlich vom Agent verwaltet.
3. **Templates sprechen nur lokal** — Unix-Socket HTTP `/run/obacht/agent.sock`
   (oder Loopback-Fallback). Per-Instance Token zur Authentifizierung.
4. **Zwei Runtimes**: `container` (Docker, Default) und `system` (systemd,
   Ausnahme für Hardware/Display). Gleiches Interface für UI/Backend.
5. **Reconcile statt push-and-pray** — desired state in DB, observed state
   aus Docker/systemd/Caddy. Loop gleicht ab.

## Stack

| Aspekt | Entscheidung |
|---|---|
| Sprache | Go 1.26+ |
| DB | SQLite (modernc.org/sqlite, kein cgo) |
| Container-Runtime | Docker Engine API (compose-go für Manifest-Subset) |
| System-Runtime | systemd via D-Bus (coreos/go-systemd) |
| Ingress | Caddy:2-alpine als Container, vom Agent gestartet |
| Backend-Connection | Socket.IO-kompatibler WS-Client (kustomized) |
| CLI | cobra + spf13/viper |
| Logging | slog (stdlib) |
| Distribution | GitHub Releases + curl\|sh Bootstrap |

## SSOT — SQLite Schema v1

Pfad: `/var/lib/obacht/agent.db` (Linux) bzw.
`~/Library/Application Support/obacht/agent.db` (macOS, für Mac-mini).

Siehe [internal/store/migrations/0001_initial.sql](../internal/store/migrations/0001_initial.sql).

Tabellen:
- `instances` — installierte Template-Instanzen (PK = instance id)
- `instance_services` — exposed services pro Instanz (für Domain-Binding)
- `domains` — Domain-Claims auf diesem Device (TLS-State)
- `ingress_bindings` — Domain → Instanz/Service Routing
- `exclusivity_locks` — z.B. `display-output`
- `instance_secrets` — per-instance IPC-Token
- `agent_meta` — Schema-Version + Misc

## Reconcile-Loop

1. Tick (default 30s) oder Trigger via WS / agentctl
2. Desired: `SELECT * FROM instances WHERE desired_state IN ('installed','stopped')`
3. Observed: Docker `container ls` (Filter `label=obacht.instance.id`), systemd
   `list-units obacht-instance-*`, Caddy admin API `/config`
4. Diff:
   - Desired ohne Observed → `runtime.Apply()`
   - Observed ohne Desired → `runtime.Remove()`
   - Beide vorhanden, aber Config-Hash ungleich → `runtime.Update()`
5. Observed-State zurück in `agent_meta` cachen + an Backend pushen

## Ingress-Modell (Caddy)

- Caddy läuft als Container `obacht-ingress` im Netzwerk `obacht-edge`.
- Volumes: `/var/lib/obacht/caddy/data` (certs), `/var/lib/obacht/caddy/config`.
- Caddyfile wird vom Agent generiert aus `domains` JOIN `ingress_bindings`
  JOIN `instance_services`.
- Reload via Caddy admin API (`POST /load`), nicht container-restart.
- ACME HTTP-01 läuft durch den obacht-proxy-Gateway (SNI-Passthrough — Port 80
  ACME-Challenge wird vom Gateway transparent durchgereicht).

## Backend-Sync

- Connection: WSS zu `api.eu.obacht.dev/ws/devices`, Socket.IO-Protokoll.
- Auth: Device-JWT aus `agent.yml`.
- **Desired State**: Backend → Agent via `agent:desired_state` Event (full
  snapshot bei (re-)connect, deltas danach).
- **Observed State**: Agent → Backend via `agent:observed_state` Event, alle
  30s + on-change.
- Capability-Handshake im `register`-Event: `{ "agent_version": "2.x.x",
  "capabilities": ["instances","ingress","system_runtime"] }`. Backend routet
  v1 vs. v2 darüber.
- REST-Fallback: `GET /devices/:id/state/desired`, `POST /devices/:id/state/observed`.

## Test-Pi (development)

- Host: `pi@raspberrypi.local` (über WG erreichbar)
- Backend-Eintrag: `meinNeuerPi`
- v1-Stand siehe [v1-state-snapshot.md](./v1-state-snapshot.md)

## Open decisions / TODOs

- IPC-Auth: per-instance Token (vs. socket gid). → **per-instance Token**
  gewählt; passt zu `instance_secrets`.
- Compose-Subset: `compose-go` von Docker einbinden (statt eigener Renderer).
- Caddy Container vs. embedded library: **Container für v1**; embedded als
  v2.x evaluieren.
- Mac-mini-Support (Loopback-Fallback statt Unix-Socket): erst nach Linux-MVP.
