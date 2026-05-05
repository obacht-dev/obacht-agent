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
    compose/      # multi-container "bundle" driver (spec v2.1+)
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

## Compose runtime (spec v2.1+)

Templates with `runtime.type: compose` are materialised by the compose
driver. Per instance:

- workspace: `/var/lib/obacht/compose/<instanceID>/docker-compose.yml`
- compose project name: `obacht-<instanceID>`
- private bundle network created by docker compose
- the manifest's `primaryService` container is additionally joined to
  the shared `obacht-edge` network so Caddy can route to it as
  `obacht-<instanceID>-<primaryService>:<primaryPort>` over docker DNS

**Image pinning** is mandatory. The registry computes a digest map at
publish time (`spec.runtime.compose.imageDigests`); the agent rewrites
every `image: <ref>` in the body to `image: <ref>@sha256:...` before
calling `docker compose up`. An unpinned image fails the install.

**Secrets** declared in `spec.secrets` substitute `${secret.<key>}`
inside the compose body. Generated values stay on the device — the api
never sees them.

**Per-service health** is reported back to the api on each observed-
state push as `services_status` (state, health, image), so the webapp
can render an expandable Components list per bundle.
