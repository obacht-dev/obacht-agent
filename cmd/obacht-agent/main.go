// obacht-agent is the long-running daemon on each device. It owns the SQLite
// SSOT, runs the reconcile loop against Docker/systemd/Caddy, and bridges to
// the obacht backend over WebSocket.
//
// Phase 1: SSOT + container reconcile. Ingress/IPC/WS land in later phases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/api"
	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/bootstrap"
	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/files"
	"github.com/obacht-dev/obacht-agent/internal/ingress"
	"github.com/obacht-dev/obacht-agent/internal/ipc"
	"github.com/obacht-dev/obacht-agent/internal/logging"
	"github.com/obacht-dev/obacht-agent/internal/reconciler"
	"github.com/obacht-dev/obacht-agent/internal/runtime/compose"
	"github.com/obacht-dev/obacht-agent/internal/runtime/container"
	"github.com/obacht-dev/obacht-agent/internal/store"
	syncpkg "github.com/obacht-dev/obacht-agent/internal/sync"
)

// agentVersion is overridden at build time via -ldflags "-X main.agentVersion=...".
var agentVersion = "dev"

func main() {
	var (
		configPath  = flag.String("config", "", "path to agent.yml (default: /etc/obacht/agent.yml)")
		logLevel    = flag.String("log-level", envOr("OBACHT_LOG_LEVEL", "info"), "debug|info|warn|error")
		dockerSock  = flag.String("docker-socket", envOr("DOCKER_HOST_SOCKET", container.DefaultSocketPath()), "path to docker.sock")
		reconcileEv = flag.Duration("reconcile-interval", 30*time.Second, "reconcile loop period")
		oneShot     = flag.Bool("once", false, "run a single reconcile pass and exit (useful for tests)")
	)
	flag.Parse()

	log := logging.New(*logLevel)
	slog.SetDefault(log)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "err", err, "path", *configPath)
		os.Exit(1)
	}
	log.Info("agent starting",
		"config", configOrDefault(*configPath),
		"state_db", cfg.Paths.StateDB,
		"server", cfg.Server.URL,
		"device_id", cfg.Server.DeviceID,
	)

	if err := os.MkdirAll(filepath.Dir(cfg.Paths.StateDB), 0o755); err != nil {
		log.Error("mkdir state dir", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := store.Open(ctx, cfg.Paths.StateDB)
	if err != nil {
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	schema, err := st.GetMeta(ctx, "schema_version")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Error("read schema_version", "err", err)
		os.Exit(1)
	}
	log.Info("store ready", "schema_version", schema)

	auditW, err := audit.New(st, cfg.Paths.AuditLog)
	if err != nil {
		log.Error("open audit log", "err", err, "path", cfg.Paths.AuditLog)
		os.Exit(1)
	}
	defer auditW.Close()
	log.Info("audit log ready", "path", cfg.Paths.AuditLog)
	_ = auditW.Append(ctx, audit.Entry{
		Op:            "agent.start",
		Actor:         "agent",
		ParamsSummary: "version=" + agentVersion,
		Params:        map[string]any{"version": agentVersion},
	})

tok, err := bootstrap.Run(ctx, log.With("component", "bootstrap"), st, cfg, agentVersion)
	if err != nil && !errors.Is(err, bootstrap.ErrSkipped) {
		// Bootstrap failure is logged but not fatal: the device may simply
		// have lost connectivity. Reconciler keeps running locally and the
		// install token is reused as a fallback for ws auth.
		log.Warn("bootstrap incomplete", "err", err)
	}
	authToken := ""
	if tok != nil {
		authToken = tok.Effective()
	}

	docker := container.New(*dockerSock)
	if err := docker.Ping(ctx); err != nil {
		log.Warn("docker not reachable; reconciler will retry on tick", "err", err, "socket", *dockerSock)
	} else {
		log.Info("docker engine reachable", "socket", *dockerSock)
	}

	rec := reconciler.New(st, docker, log.With("component", "reconciler"), *reconcileEv)
	rec.SetSocketPath(cfg.Paths.Socket)

	// Compose runtime driver — bundle templates (spec v2.1).
	if err := os.MkdirAll(cfg.Paths.ComposeRoot, 0o750); err != nil {
		log.Warn("mkdir compose root", "err", err, "path", cfg.Paths.ComposeRoot)
	}
	composeDrv := compose.New(cfg.Paths.ComposeRoot, st, log.With("component", "compose"))
	rec.SetCompose(composeDrv)

	// Ingress (Caddy). Bootstrapped lazily in the background — pulling the
	// Caddy image can take a while and we don't want to block IPC startup.
	ingMgr := ingress.New(docker, st, cfg.Ingress, cfg.Paths, log.With("component", "ingress"))
	if !cfg.Ingress.Disabled {
		rec.SetIngress(ingMgr)
		go func() {
			if err := ingMgr.Bootstrap(ctx); err != nil {
				log.Warn("ingress bootstrap failed; will retry on reconcile", "err", err)
			}
		}()
	}

	if *oneShot {
		if err := rec.RunOnce(ctx); err != nil {
			log.Error("reconcile once", "err", err)
			os.Exit(1)
		}
		log.Info("reconcile once complete")
		return
	}

	ipcSrv := ipc.New(cfg.Paths.Socket, st, rec, log.With("component", "ipc"))
	ipcSrv.SetIngress(ingMgr)
	ipcSrv.SetAudit(auditW)
	ipcSrv.SetVersion(agentVersion)
	if err := ipcSrv.Listen(ctx); err != nil {
		log.Error("ipc listen", "err", err)
		os.Exit(1)
	}

	go rec.Run(ctx)

	// Backend channel (Socket.IO v4). Skipped if no server configured.
	if cfg.Server.URL != "" && authToken != "" {
		wsClient := api.New(cfg.Server.URL, authToken, log.With("component", "ws"))
		syncer := syncpkg.New(wsClient, st, rec, cfg.Server.DeviceID, agentVersion, log.With("component", "sync"), auditW)
		files.New(wsClient, st, log.With("component", "files")).Register()
		go wsClient.Run(ctx)
		go syncer.Run(ctx)
	} else {
		log.Info("backend channel disabled (no server.url or auth token)")
	}

	<-ctx.Done()
	log.Info("agent shutting down")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func configOrDefault(p string) string {
	if p == "" {
		return config.DefaultPath()
	}
	return p
}

// keep imports honest if other packages get added later
var _ = fmt.Sprintf
