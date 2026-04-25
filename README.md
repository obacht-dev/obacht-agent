# obacht-agent (v2)

Device-side daemon + CLI for the obacht platform. Single source of truth per
device (SQLite), reconcile-loop against Docker / systemd / Caddy, agent-owned
ingress (TLS termination on device), and a small local IPC for templates.

> **Status:** scaffolding (Phase 0). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Layout

```
cmd/
  obacht-agent/   # daemon entry
  obachtctl/      # control CLI (talks to daemon over /run/obacht/agent.sock)
internal/
  api/            # backend WS client (api.eu.obacht.dev)
  bootstrap/      # first-boot install-token → device JWT exchange
  config/         # /etc/obacht/agent.yml loader
  ingress/        # Caddy container manager + Caddyfile generator
  ipc/            # Unix-socket HTTP for templates and obachtctl
  logging/        # slog setup
  reconciler/     # desired-vs-observed loop
  runtime/
    container/    # Docker Engine API driver
    system/       # systemd D-Bus driver
  store/          # SQLite SSOT + migrations
  telemetry/      # CPU/RAM/disk → backend
test/             # iterative integration tests against pi@raspberrypi.local
docs/             # architecture, sdk, snapshots
```

## Quickstart (development)

```bash
# Build daemon for current host
go build ./cmd/obacht-agent
go build ./cmd/obachtctl

# Cross-build for Raspberry Pi (aarch64 / Debian trixie)
GOOS=linux GOARCH=arm64 go build -o build/obacht-agent-linux-arm64 ./cmd/obacht-agent
GOOS=linux GOARCH=arm64 go build -o build/obachtctl-linux-arm64 ./cmd/obachtctl
```

## Test pi

`pi@raspberrypi.local` (registered as `meinNeuerPi` in obacht backend, reachable
via WireGuard). All `test/0X-*.sh` scripts run against it.
