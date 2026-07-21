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
	"os/user"
	"path/filepath"
	goruntime "runtime"
	"strings"
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
	logspkg "github.com/obacht-dev/obacht-agent/internal/logs"
	"github.com/obacht-dev/obacht-agent/internal/reconciler"
	"github.com/obacht-dev/obacht-agent/internal/runtime/compose"
	"github.com/obacht-dev/obacht-agent/internal/runtime/container"
	"github.com/obacht-dev/obacht-agent/internal/selfupdate"
	"github.com/obacht-dev/obacht-agent/internal/signedmut"
	"github.com/obacht-dev/obacht-agent/internal/store"
	syncpkg "github.com/obacht-dev/obacht-agent/internal/sync"
)

// agentVersion is overridden at build time via -ldflags "-X main.agentVersion=...".
var agentVersion = "dev"

func main() {
	// Subcommands are handled before the daemon flag set so the installer
	// can call `obacht-agent verify-release ...` on the CURRENTLY installed
	// (trusted) binary to check a new release before swapping it in.
	if len(os.Args) > 1 && os.Args[1] == "verify-release" {
		os.Exit(runVerifyRelease(os.Args[2:]))
	}

	var (
		configPath  = flag.String("config", "", "path to agent.yml (default: /etc/obacht/agent.yml)")
		logLevel    = flag.String("log-level", envOr("OBACHT_LOG_LEVEL", "info"), "debug|info|warn|error")
		dockerSock  = flag.String("docker-socket", envOr("DOCKER_HOST_SOCKET", container.DefaultSocketPath()), "path to docker.sock")
		reconcileEv = flag.Duration("reconcile-interval", 30*time.Second, "reconcile loop period")
		oneShot     = flag.Bool("once", false, "run a single reconcile pass and exit (useful for tests)")
		wgIP        = flag.String("wireguard-ip", "", "override the obacht WG IP reported in telemetry (macOS)")
		hostGateway = flag.String("host-gateway", envOr("OBACHT_HOST_GATEWAY", ""), "VZ gateway IP that VM containers use to reach the macOS host; resolves ${host.gateway} (macOS host-services)")
	)
	flag.Parse()

	// Normalize the build version to clean semver (strip any leading "v" from
	// the git tag, e.g. "v0.3.19" -> "0.3.19"). The backend stores and compares
	// agent_version as bare semver, so reporting it with a "v" prefix would
	// break update-available detection.
	agentVersion = strings.TrimPrefix(agentVersion, "v")

	log := logging.New(*logLevel)
	slog.SetDefault(log)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "err", err, "path", *configPath)
		os.Exit(1)
	}
	if *wgIP != "" {
		cfg.Telemetry.WireguardIP = *wgIP
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
	rec.SetHostGateway(*hostGateway)

	// Compose runtime driver — bundle templates (spec v2.1).
	if err := os.MkdirAll(cfg.Paths.ComposeRoot, 0o750); err != nil {
		log.Warn("mkdir compose root", "err", err, "path", cfg.Paths.ComposeRoot)
	}
	composeDrv := compose.New(cfg.Paths.ComposeRoot, st, compose.DockerCLI{
		Bin:       cfg.Docker.Bin,
		Host:      cfg.Docker.Host,
		ConfigDir: cfg.Docker.ConfigDir,
	}, log.With("component", "compose"))
	rec.SetCompose(composeDrv)

	// Ingress (Caddy). Bootstrapped lazily in the background — pulling the
	// Caddy image can take a while and we don't want to block IPC startup.
	ingMgr := ingress.New(docker, st, cfg.Ingress, cfg.Paths, log.With("component", "ingress"))
	ingMgr.SetHostGateway(*hostGateway) // VZ gateway for Mac local-port forwarding (empty on Pis)
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

	// One-time migration (PLAN-PI-SIGNED-MUTATIONS A3b, linux only): adopt
	// the install-provisioned SSH key from authorized_keys as the pinned
	// signing key. Runs before the trust store is first read below.
	importUserKeysOnce(ctx, st, cfg.Paths.UserKeysDir, auditW, log)

	ipcSrv := ipc.New(cfg.Paths.Socket, st, rec, log.With("component", "ipc"))
	ipcSrv.SetIngress(ingMgr)
	ipcSrv.SetAudit(auditW)
	ipcSrv.SetVersion(agentVersion)
	ipcSrv.SetUserKeysDir(cfg.Paths.UserKeysDir)
	if err := ipcSrv.Listen(ctx); err != nil {
		log.Error("ipc listen", "err", err)
		os.Exit(1)
	}

	// Compose pre-pull runs through the container driver's REST pull path so
	// bundle installs share the pull-progress pipeline (D1.2). Wired
	// unconditionally: without a WS/progress sink it is just a plain pull.
	composeDrv.SetImagePuller(docker.PullImageFor)

	// Backend channel (Socket.IO v4). Skipped if no server configured.
	// NOTE: rec.Run starts *after* this block so the change notifier and
	// progress sink are wired before the first reconcile pass (no races).
	if cfg.Server.URL != "" && authToken != "" {
		wsClient := api.New(cfg.Server.URL, authToken, log.With("component", "ws"))
		syncer := syncpkg.New(wsClient, st, rec, cfg.Server.DeviceID, agentVersion, log.With("component", "sync"), auditW)
		syncer.SetCompose(composeDrv)
		syncer.SetWireguardIPOverride(cfg.Telemetry.WireguardIP)

		// Device-responsiveness wiring (PLAN-DEVICE-RESPONSIVENESS-V1):
		// real state transitions push observed snapshots immediately (A2),
		// and pull/create/start phases stream as transient, never-persisted
		// progress events (D1).
		rec.SetChangeNotifier(syncer.PushNow)
		rec.SetProgress(syncer)
		docker.SetProgress(syncer)
		composeDrv.SetProgress(syncer)

		// Signed mutations: load the user pubkeys pinned at enrollment.
		// No keys -> capability not advertised, handler denies everything.
		userKeys, keyProblems := signedmut.LoadUserKeys(cfg.Paths.UserKeysDir)
		for _, p := range keyProblems {
			log.Warn("user key skipped", "err", p)
		}
		if len(userKeys) > 0 {
			labels := make([]string, 0, len(userKeys))
			for _, k := range userKeys {
				labels = append(labels, k.Label+" ("+k.Fingerprint()+")")
			}
			log.Info("signed mutations enabled", "keys", strings.Join(labels, ", "))
		}
		syncer.SetSignedMutations(signedmut.NewVerifier(userKeys), ingMgr)
		// obachtctl trust pin/unpin (IPC) hot-swaps the verifier and
		// re-registers, so the capability flips without an agent restart.
		ipcSrv.SetOnUserKeysChanged(func() (int, []error) {
			return syncer.ReloadUserKeys(cfg.Paths.UserKeysDir)
		})
		// power_mode gates the runtime.system capability — re-register on
		// setting flips so the backend routes (or stops routing) system
		// installs without an agent restart.
		ipcSrv.SetOnSystemSettingChanged(func(string) { syncer.Reregister() })
		files.New(wsClient, st, log.With("component", "files")).Register()
		logspkg.New(wsClient, log.With("component", "logs")).Register()
		go wsClient.Run(ctx)
		go syncer.Run(ctx)
	} else {
		log.Info("backend channel disabled (no server.url or auth token)")
	}

	go rec.Run(ctx)

	<-ctx.Done()
	log.Info("agent shutting down")
}

// userKeysImportedMetaKey marks the one-time authorized_keys import as done
// so a later, deliberate unpin (emptying user-keys.d) is not silently undone
// on the next start.
const userKeysImportedMetaKey = "user_keys_imported"

// importUserKeysOnce migrates the install-provisioned SSH public key into
// the signed-mutation trust store (PLAN-PI-SIGNED-MUTATIONS §4.2). Linux
// only — the Mac app pins explicitly at enrollment and has no sshd. Safe by
// construction: every key in authorized_keys can already open an SSH session
// as the obacht user and drive obachtctl, i.e. it holds strictly MORE power
// than a mutation signer, so adopting it grants nothing new. Runs at most
// once (agent_meta marker); skipped entirely when keys are already pinned
// (fresh installs where install.sh provisioned user-keys.d directly).
func importUserKeysOnce(ctx context.Context, st *store.Store, dir string, auditW *audit.Writer, log *slog.Logger) {
	if goruntime.GOOS != "linux" {
		return
	}
	if v, err := st.GetMeta(ctx, userKeysImportedMetaKey); err == nil && v != "" {
		return
	}
	if keys, _ := signedmut.LoadUserKeys(dir); len(keys) > 0 {
		_ = st.SetMeta(ctx, userKeysImportedMetaKey, "preexisting")
		return
	}
	authPath := authorizedKeysPath()
	if authPath == "" {
		return
	}
	pinned, skipped, err := signedmut.ImportAuthorizedKeys(dir, authPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// Unreadable file: retry on the next start rather than burning
			// the marker on a transient error.
			log.Warn("user-key import failed", "path", authPath, "err", err)
		}
		return
	}
	for _, k := range pinned {
		log.Info("user key imported from authorized_keys", "fingerprint", k.Fingerprint())
		_ = auditW.Append(ctx, audit.Entry{
			Op:            "security.user_key.imported",
			Actor:         "agent",
			Target:        k.Fingerprint(),
			Result:        audit.ResultOK,
			ParamsSummary: "source=authorized_keys",
			Params:        map[string]any{"fingerprint": k.Fingerprint(), "label": k.Label, "source": authPath},
		})
	}
	if skipped > 0 {
		log.Info("user-key import skipped non-ed25519/option lines", "count", skipped)
	}
	_ = st.SetMeta(ctx, userKeysImportedMetaKey, time.Now().UTC().Format(time.RFC3339))
}

// authorizedKeysPath resolves the obacht user's authorized_keys file. The
// agent normally runs AS obacht, but resolve the account explicitly so a
// root-run agent (legacy installs) still finds the right file.
func authorizedKeysPath() string {
	if u, err := user.Lookup("obacht"); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".ssh", "authorized_keys")
	}
	return ""
}

// runVerifyRelease implements `obacht-agent verify-release --file <f>
// --sig <f.minisig>`: it verifies a release artifact against the embedded
// offline release-signing key(s). The installer runs this on the OLD,
// already-trusted binary before swapping in a new one.
//
// Exit codes are a contract with install.sh / obacht-self-update:
//
//	0  verified OK        → proceed with the swap
//	1  signature REJECTED → abort (a real tampering signal, never skip)
//	2  cannot verify      → no embedded keys yet (signing-migration
//	                        window) or bad usage; installer may fall back
//	                        to sha256+TLS and warn.
func runVerifyRelease(args []string) int {
	fs := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	file := fs.String("file", "", "path to the artifact to verify (tarball or install.sh)")
	sig := fs.String("sig", "", "path to the detached .minisig signature")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *sig == "" {
		fmt.Fprintln(os.Stderr, "verify-release: --file and --sig are required")
		return 2
	}
	content, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-release: read file: %v\n", err)
		return 2
	}
	sigBytes, err := os.ReadFile(*sig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-release: read sig: %v\n", err)
		return 2
	}
	switch err := selfupdate.VerifyFile(content, sigBytes); {
	case err == nil:
		fmt.Fprintf(os.Stderr, "verify-release: OK (%s)\n", filepath.Base(*file))
		return 0
	case errors.Is(err, selfupdate.ErrNoKeys):
		fmt.Fprintln(os.Stderr, "verify-release: no release keys trusted (unsigned-migration window)")
		return 2
	default:
		fmt.Fprintf(os.Stderr, "verify-release: SIGNATURE REJECTED: %v\n", err)
		return 1
	}
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
