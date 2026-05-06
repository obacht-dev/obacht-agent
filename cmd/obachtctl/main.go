// obachtctl is the device-local control CLI. It speaks to the agent daemon
// over its unix-socket IPC by default; falls back to direct SQLite access
// when --db is given (useful for tests where the daemon is not running).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/store"
	"github.com/obacht-dev/obacht-agent/internal/trust"
	"gopkg.in/yaml.v3"
)

// trustDir is where the agent operator drops minisign .pub files for
// the registry signing key(s). Overridable via OBACHT_TRUST_DIR for
// tests. We fail-closed: if both --manifest-base64 and --signature-
// base64 are provided to `template install`, verification is required
// and a missing trust dir means rejection.
const defaultTrustDir = "/etc/obacht/trust.d"

func trustDir() string {
	if d := os.Getenv("OBACHT_TRUST_DIR"); d != "" {
		return d
	}
	return defaultTrustDir
}

const cliVersion = "0.1.0"

func main() {
	flag.Usage = func() { usage(os.Stderr) }
	socket := flag.String("socket", config.DefaultSocket(), "path to agent unix socket")
	dbPath := flag.String("db", "", "bypass IPC and write directly to SQLite (testing only)")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}

	ctx := context.Background()
	rt := &runtime{socket: *socket, dbPath: *dbPath}

	switch args[0] {
	case "version":
		fmt.Println(cliVersion)
	case "health":
		rt.cmdHealth(ctx)
	case "instance":
		rt.cmdInstance(ctx, args[1:])
	case "template":
		rt.cmdTemplate(ctx, args[1:])
	case "domain":
		rt.cmdDomain(ctx, args[1:])
	case "ingress":
		rt.cmdIngress(ctx, args[1:])
	case "reconcile":
		rt.cmdReconcile(ctx, args[1:])
	case "audit":
		rt.cmdAudit(ctx, args[1:])
	case "service":
		rt.cmdService(ctx, args[1:])
	case "system":
		rt.cmdSystem(ctx, args[1:])
	case "logs":
		rt.cmdLogs(ctx, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		usage(os.Stderr)
		os.Exit(2)
	}
}

type runtime struct {
	socket string
	dbPath string
}

func (r *runtime) directMode() bool { return r.dbPath != "" }

// --- HTTP client over unix socket ---

func (r *runtime) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", r.socket)
			},
		},
	}
}

func (r *runtime) doIPC(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ipc %s %s: %w (is the agent running? socket=%s)", method, path, err, r.socket)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

// --- direct SQLite mode (fallback for tests) ---

func (r *runtime) openStore(ctx context.Context) (*store.Store, error) {
	if err := os.MkdirAll(filepath.Dir(r.dbPath), 0o755); err != nil {
		return nil, err
	}
	return store.Open(ctx, r.dbPath)
}

// --- commands ---

func (r *runtime) cmdHealth(ctx context.Context) {
	if r.directMode() {
		fmt.Println(`{"ok":true,"mode":"direct"}`)
		return
	}
	code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/health", nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) cmdReconcile(ctx context.Context, args []string) {
	if len(args) == 0 || args[0] != "trigger" {
		die("usage: obachtctl reconcile trigger")
	}
	if r.directMode() {
		die("reconcile trigger requires the daemon (not available in --db mode)")
	}
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/reconcile", nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) cmdInstance(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("usage: obachtctl instance <list|upsert|remove|secret|set-state>")
	}
	switch args[0] {
	case "list":
		r.instanceList(ctx)
	case "upsert":
		r.instanceUpsert(ctx, args[1:])
	case "remove":
		r.instanceRemove(ctx, args[1:])
	case "secret":
		r.instanceSecret(ctx, args[1:])
	case "set-state":
		r.instanceSetState(ctx, args[1:])
	default:
		die("unknown instance subcommand: %s", args[0])
	}
}

func (r *runtime) instanceList(ctx context.Context) {
	if r.directMode() {
		st, err := r.openStore(ctx)
		if err != nil {
			die("open store: %v", err)
		}
		defer st.Close()
		insts, err := st.ListInstances(ctx)
		if err != nil {
			die("list: %v", err)
		}
		out := make([]map[string]any, 0, len(insts))
		for _, i := range insts {
			out = append(out, map[string]any{
				"id":            i.ID,
				"template_id":   i.TemplateID,
				"runtime":       string(i.Runtime),
				"version":       i.Version,
				"desired_state": string(i.DesiredState),
				"observed_state": i.ObservedState,
			})
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/admin/instances", nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) instanceUpsert(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("instance upsert", flag.ExitOnError)
	id := fs.String("id", "", "instance id (required)")
	templateID := fs.String("template", "", "template id (required)")
	rt := fs.String("runtime", "container", "container|system")
	version := fs.String("version", "", "version tag")
	desired := fs.String("state", "installed", "installed|stopped|removed")
	configFile := fs.String("config-file", "", "path to JSON spec; '-' for stdin")
	_ = fs.Parse(args)
	if *id == "" || *templateID == "" {
		die("--id and --template are required")
	}
	var configRaw any
	if *configFile != "" {
		b, err := readFileOrStdin(*configFile)
		if err != nil {
			die("read config: %v", err)
		}
		var asJSON any
		if err := json.Unmarshal(b, &asJSON); err != nil {
			die("config-file is not valid JSON: %v", err)
		}
		configRaw = asJSON
	}
	if r.directMode() {
		st, err := r.openStore(ctx)
		if err != nil {
			die("open store: %v", err)
		}
		defer st.Close()
		cfgJSON := ""
		if configRaw != nil {
			b, _ := json.Marshal(configRaw)
			cfgJSON = string(b)
		}
		err = st.UpsertInstance(ctx, store.Instance{
			ID:           *id,
			TemplateID:   *templateID,
			Runtime:      store.Runtime(*rt),
			Version:      *version,
			DesiredState: store.DesiredState(*desired),
			ConfigJSON:   cfgJSON,
		})
		if err != nil {
			die("upsert: %v", err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "id": *id})
		return
	}
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/instances", map[string]any{
		"id":            *id,
		"template_id":   *templateID,
		"runtime":       *rt,
		"version":       *version,
		"desired_state": *desired,
		"config":        configRaw,
	})
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) instanceRemove(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("instance remove", flag.ExitOnError)
	id := fs.String("id", "", "instance id (required)")
	hard := fs.Bool("hard", false, "delete row outright instead of marking desired_state=removed")
	_ = fs.Parse(args)
	if *id == "" {
		die("--id is required")
	}
	if r.directMode() {
		st, err := r.openStore(ctx)
		if err != nil {
			die("open store: %v", err)
		}
		defer st.Close()
		if *hard {
			if err := st.DeleteInstance(ctx, *id); err != nil {
				die("delete: %v", err)
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "deleted": *id})
			return
		}
		got, err := st.GetInstance(ctx, *id)
		if err != nil {
			die("get instance: %v", err)
		}
		got.DesiredState = store.DesiredRemoved
		if err := st.UpsertInstance(ctx, *got); err != nil {
			die("update: %v", err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "marked_removed": *id})
		return
	}
	path := "/v1/admin/instances/" + *id
	if *hard {
		path += "?hard=1"
	}
	code, body, err := r.doIPC(ctx, http.MethodDelete, path, nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) instanceSecret(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("instance secret", flag.ExitOnError)
	id := fs.String("id", "", "instance id (required)")
	_ = fs.Parse(args)
	if *id == "" {
		die("--id is required")
	}
	if r.directMode() {
		st, err := r.openStore(ctx)
		if err != nil {
			die("open store: %v", err)
		}
		defer st.Close()
		secret, err := st.CreateInstanceSecret(ctx, *id)
		if err != nil {
			die("issue secret: %v", err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "secret": secret})
		return
	}
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/instances/"+*id+"/secret", nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

// instanceSetState flips the desired state of an existing instance to
// "stopped" or "installed" via the lighter-weight IPC route. Unlike
// `instance upsert`, the caller does NOT need to know the template id
// or config — the agent reads them from the existing row.
func (r *runtime) instanceSetState(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("instance set-state", flag.ExitOnError)
	id := fs.String("id", "", "instance id (required)")
	state := fs.String("state", "", "installed|stopped (required)")
	_ = fs.Parse(args)
	if *id == "" || *state == "" {
		die("--id and --state are required")
	}
	if *state != "installed" && *state != "stopped" {
		die("--state must be 'installed' or 'stopped'")
	}
	body, _ := json.Marshal(map[string]string{"state": *state})
	code, resp, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/instances/"+*id+"/state", body)
	if err != nil {
		die("%v", err)
	}
	emit(code, resp)
}

// --- domain / ingress commands ---

func (r *runtime) cmdDomain(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("usage: obachtctl domain <list|claim|unclaim|bind|unbind|service>")
	}
	switch args[0] {
	case "list":
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/admin/domains", nil)
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	case "claim":
		fs := flag.NewFlagSet("domain claim", flag.ExitOnError)
		domain := fs.String("domain", "", "fqdn (required)")
		_ = fs.Bool("json", false, "output JSON (default)")
		_ = fs.Parse(args[1:])
		if *domain == "" {
			die("--domain is required")
		}
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/domains", map[string]any{
			"domain":         *domain,
			"desired_status": "ready",
		})
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	case "unclaim":
		fs := flag.NewFlagSet("domain unclaim", flag.ExitOnError)
		domain := fs.String("domain", "", "fqdn (required)")
		_ = fs.Bool("json", false, "output JSON (default)")
		_ = fs.Parse(args[1:])
		if *domain == "" {
			die("--domain is required")
		}
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodDelete, "/v1/admin/domains/"+*domain, nil)
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	case "bind":
		fs := flag.NewFlagSet("domain bind", flag.ExitOnError)
		domain := fs.String("domain", "", "fqdn (required)")
		instID := fs.String("instance", "", "instance id (required)")
		svc := fs.String("service", "", "service name (required)")
		mode := fs.String("mode", "root", "root|path")
		prefix := fs.String("path-prefix", "", "path prefix (when mode=path)")
		localPort := fs.Int("local-port", 0, "bind to a local TCP port instead of an instance/service")
		_ = fs.Bool("json", false, "output JSON (default)")
		_ = fs.Parse(args[1:])
		if *domain == "" {
			die("--domain is required")
		}
		if *localPort > 0 {
			if *instID != "" || *svc != "" {
				die("--local-port is mutually exclusive with --instance/--service")
			}
			r.requireIPC()
			code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/bindings", map[string]any{
				"domain":      *domain,
				"target_type": "host_port",
				"target":      fmt.Sprintf("127.0.0.1:%d", *localPort),
				"mode":        *mode,
				"path_prefix": *prefix,
			})
			if err != nil {
				die("%v", err)
			}
			emit(code, body)
			return
		}
		if *instID == "" || *svc == "" {
			die("--domain plus either --instance/--service or --local-port required")
		}
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/bindings", map[string]any{
			"domain":       *domain,
			"instance_id":  *instID,
			"service_name": *svc,
			"mode":         *mode,
			"path_prefix":  *prefix,
		})
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	case "unbind":
		fs := flag.NewFlagSet("domain unbind", flag.ExitOnError)
		domain := fs.String("domain", "", "fqdn (required)")
		_ = fs.Bool("json", false, "output JSON (default)")
		_ = fs.Parse(args[1:])
		if *domain == "" {
			die("--domain is required")
		}
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodDelete, "/v1/admin/bindings/"+*domain, nil)
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	case "service":
		fs := flag.NewFlagSet("domain service", flag.ExitOnError)
		instID := fs.String("instance", "", "instance id (required)")
		svc := fs.String("service", "", "service name (required)")
		ttype := fs.String("type", "docker_dns", "host_port|docker_dns|unix_socket")
		target := fs.String("target", "", "target string, e.g. \"obacht-myapp:80\" (required)")
		_ = fs.Parse(args[1:])
		if *instID == "" || *svc == "" || *target == "" {
			die("--instance, --service, --target required")
		}
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/services", map[string]any{
			"instance_id":  *instID,
			"service_name": *svc,
			"target_type":  *ttype,
			"target":       *target,
		})
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	default:
		die("unknown domain subcommand: %s", args[0])
	}
}

func (r *runtime) cmdIngress(ctx context.Context, args []string) {
	if len(args) == 0 || args[0] != "reload" {
		die("usage: obachtctl ingress reload")
	}
	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/ingress/reload", nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) cmdAudit(ctx context.Context, args []string) {
	if len(args) == 0 || args[0] != "tail" {
		die("usage: obachtctl audit tail [--n N]")
	}
	fs := flag.NewFlagSet("audit tail", flag.ExitOnError)
	n := fs.Int("n", 50, "number of entries (newest first)")
	_ = fs.Parse(args[1:])
	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodGet, fmt.Sprintf("/v1/admin/audit?n=%d", *n), nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) cmdSystem(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("usage: obachtctl system <status|set-power-mode|unlock-power|lock-power|update-agent>")
	}
	switch args[0] {
	case "status":
		r.requireIPC()
		code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/system/status", nil)
		if err != nil {
			die("%v", err)
		}
		emit(code, body)
	case "set-power-mode":
		r.systemSetPowerMode(ctx, args[1:])
	case "unlock-power":
		r.systemUnlockPower(ctx, args[1:])
	case "lock-power":
		r.systemLockPower(ctx, args[1:])
	case "update-agent":
		r.systemUpdateAgent(ctx, args[1:])
	default:
		die("unknown system subcommand: %s", args[0])
	}
}

// systemUpdateAgent shells out to the privileged self-update wrapper
// installed at /usr/local/sbin/obacht-self-update. The wrapper itself
// is a fixed-content shell script that re-runs install.sh in
// --self-update mode, so the only argv we control is the version tag
// (or "latest"). The caller does not need to be root — sudo is
// gated by the obacht-bootstrap sudoers fragment.
func (r *runtime) systemUpdateAgent(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("system update-agent", flag.ExitOnError)
	version := fs.String("version", "latest", "release tag (e.g. v0.3.7) or 'latest'")
	_ = fs.Parse(args)
	if *version == "" {
		die("--version cannot be empty")
	}
	// Validate against the same regex the helper enforces, so we fail
	// fast with a useful message rather than letting sudo error out.
	if *version != "latest" {
		ok := len(*version) > 1 && (*version)[0] == 'v'
		if ok {
			for _, c := range (*version)[1:] {
				if !(c >= '0' && c <= '9') && c != '.' {
					ok = false
					break
				}
			}
		}
		if !ok {
			die("--version must be 'latest' or vX.Y.Z, got %q", *version)
		}
	}
	cmd := exec.CommandContext(ctx, "sudo", "-n", "/usr/local/sbin/obacht-self-update", *version)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		die("obacht-self-update failed: %v", err)
	}
}

// systemSetPowerMode toggles the power_mode flag in system_settings.
// The install-plan unlock-power step shells out to this. Power mode
// itself doesn't grant the agent any new capability today (S2.3) — it
// is the gate Phase S5 will check before unlocking restricted commands.
func (r *runtime) systemSetPowerMode(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("system set-power-mode", flag.ExitOnError)
	enable := fs.Bool("enable", false, "enable power mode")
	disable := fs.Bool("disable", false, "disable power mode")
	_ = fs.Bool("json", false, "output JSON (default)")
	_ = fs.Parse(args)
	if *enable == *disable {
		die("exactly one of --enable / --disable is required")
	}
	val := "false"
	if *enable {
		val = "true"
	}
	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/system/settings", map[string]any{
		"key":   "power_mode",
		"value": val,
	})
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

// cmdLogs returns docker logs for an instance's container/service.
// Read-only; matches the IPC endpoint signature 1:1.
//
//	obachtctl logs --instance=<id> [--service=<name>] [--tail=200]
func (r *runtime) cmdLogs(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	instance := fs.String("instance", "", "instance id (required)")
	service := fs.String("service", "", "compose service name (required for compose instances)")
	tail := fs.Int("tail", 200, "number of trailing log lines (max 5000)")
	_ = fs.Parse(args)
	if *instance == "" {
		die("--instance is required")
	}
	r.requireIPC()
	q := fmt.Sprintf("?tail=%d", *tail)
	if *service != "" {
		q += "&service=" + *service
	}
	code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/admin/instances/"+*instance+"/logs"+q, nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

// cmdTemplate is the install-plan-friendly façade over instance+ipc.
// The api builds plans like `template install --id static-site --instance
// blog --json [--version v] [--config-json {...}]` so the ssh-gateway
// can run them verbatim. Keeping the cli surface stable across the
// install-plan boundary means the api can be changed without re-rolling
// agents on every Pi.

// systemUnlockPower is the operator-facing two-step Power Mode
// unlock.
//
// Why two steps: Power Mode lets the agent execute a small set of
// privileged commands via sudo (see obacht-power-toggle). Flipping it
// on is high-impact, so we make it deliberately interactive:
//
//   1. Without --yes, we print what's about to change, generate a
//      random 6-char confirm-code, ask the operator to type it back.
//   2. On match, we shell out to `sudo obacht-power-toggle enable`
//      AND set the agent's power_mode setting via IPC, so the
//      reconciler / future template installs see it.
//
// Non-interactive use (CI / install-plan via ssh-gateway):
//   obachtctl system unlock-power --yes
//
// The --token / --confirm flow used by the obacht-api unlock-power
// install-plan endpoint is upstream of this binary; the api validates
// the operator's webapp confirmation, then issues a plan that calls
// `system unlock-power --yes` here.
func (r *runtime) systemUnlockPower(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("system unlock-power", flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip the interactive confirm-code prompt")
	togglePath := fs.String("toggle-binary", "/usr/local/sbin/obacht-power-toggle",
		"path to obacht-power-toggle (override for tests)")
	skipSudo := fs.Bool("skip-sudo", false, "skip the sudo obacht-power-toggle call (for tests; sets only the IPC flag)")
	_ = fs.Bool("json", false, "output JSON (default)")
	_ = fs.Parse(args)

	if !*yes {
		if err := interactiveConfirm("UNLOCK Power Mode (allow privileged commands)"); err != nil {
			die("%v", err)
		}
	}

	if !*skipSudo {
		// Try without sudo first when running as root (e.g. in the
		// agent process) — the sudoers entry only kicks in for the
		// `obacht` user. This makes the ssh-gateway-driven path work
		// regardless of whether the agent is running as root or as
		// `obacht`.
		var cmd *exec.Cmd
		if os.Geteuid() == 0 {
			cmd = exec.CommandContext(ctx, *togglePath, "enable")
		} else {
			cmd = exec.CommandContext(ctx, "sudo", "-n", *togglePath, "enable")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			die("obacht-power-toggle enable: %v\n%s", err, out)
		}
	}

	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/system/settings", map[string]any{
		"key":   "power_mode",
		"value": "true",
	})
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

// systemLockPower disables Power Mode. Always safe to run, even if
// already locked. We still confirm interactively unless --yes, because
// it can break running 'power'-level templates.
func (r *runtime) systemLockPower(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("system lock-power", flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip the interactive confirm-code prompt")
	togglePath := fs.String("toggle-binary", "/usr/local/sbin/obacht-power-toggle",
		"path to obacht-power-toggle (override for tests)")
	skipSudo := fs.Bool("skip-sudo", false, "skip the sudo obacht-power-toggle call (for tests)")
	_ = fs.Bool("json", false, "output JSON (default)")
	_ = fs.Parse(args)

	if !*yes {
		if err := interactiveConfirm("LOCK Power Mode (revoke privileged commands)"); err != nil {
			die("%v", err)
		}
	}

	if !*skipSudo {
		var cmd *exec.Cmd
		if os.Geteuid() == 0 {
			cmd = exec.CommandContext(ctx, *togglePath, "disable")
		} else {
			cmd = exec.CommandContext(ctx, "sudo", "-n", *togglePath, "disable")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			die("obacht-power-toggle disable: %v\n%s", err, out)
		}
	}

	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/system/settings", map[string]any{
		"key":   "power_mode",
		"value": "false",
	})
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

// interactiveConfirm prints `action` and asks the operator to type a
// random 6-character code back. Returns nil if the input matches,
// non-nil error otherwise.
//
// We use crypto/rand for the code so the operator can't predict it
// (defense against a malicious script piping `yes` into the command).
// 60-second timeout: long enough for a careful read, short enough to
// matter against accidental shoulder-surfing replays.
func interactiveConfirm(action string) error {
	codeBytes := make([]byte, 4)
	if _, err := rand.Read(codeBytes); err != nil {
		return fmt.Errorf("generate confirm code: %w", err)
	}
	// 6 hex chars, easy to read aloud, hard to brute force in 60s.
	code := fmt.Sprintf("%x", codeBytes)[:6]

	fmt.Fprintf(os.Stderr, "\n  About to: %s\n", action)
	fmt.Fprintf(os.Stderr, "  Type this code to confirm (60s): %s\n  > ", code)

	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var s string
		_, err := fmt.Fscanln(os.Stdin, &s)
		ch <- res{strings.TrimSpace(s), err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("read confirm code: %w", r.err)
		}
		if r.s != code {
			return fmt.Errorf("confirm code did not match")
		}
		return nil
	case <-time.After(60 * time.Second):
		return fmt.Errorf("confirm code not entered within 60s")
	}
}


func (r *runtime) cmdTemplate(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("usage: obachtctl template <install|uninstall>")
	}
	switch args[0] {
	case "install":
		r.templateInstall(ctx, args[1:])
	case "uninstall":
		r.templateUninstall(ctx, args[1:])
	default:
		die("unknown template subcommand: %s", args[0])
	}
}

func (r *runtime) templateInstall(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("template install", flag.ExitOnError)
	tid := fs.String("id", "", "template id (required)")
	iid := fs.String("instance", "", "instance id (required)")
	version := fs.String("version", "", "version tag")
	configJSON := fs.String("config-json", "", "materialized container spec as JSON string")
	manifestB64 := fs.String("manifest-base64", "", "base64-encoded raw manifest bytes (S4 trust)")
	signatureB64 := fs.String("signature-base64", "", "base64-encoded minisign signature (S4 trust)")
	_ = fs.Bool("json", false, "output JSON (default)")
	_ = fs.Parse(args)
	if *tid == "" || *iid == "" {
		die("--id and --instance are required")
	}

	// S4: minisign trust check. Fail-closed semantics:
	//   - if either flag is provided, BOTH must be provided
	//   - the local trust bundle must contain at least one trusted key
	//   - signature must verify against the manifest content
	// During the S4 rollout the api may omit both flags for templates
	// that pre-date signing; in that case we permit the install but
	// audit-record it as unsigned (the agent's reconciler can flag
	// these in /system/status for the operator).
	if (*manifestB64 != "") != (*signatureB64 != "") {
		die("--manifest-base64 and --signature-base64 must be used together")
	}
	if *manifestB64 != "" {
		manifest, err := decodeB64(*manifestB64)
		if err != nil {
			die("--manifest-base64 not valid base64: %v", err)
		}
		sig, err := decodeB64(*signatureB64)
		if err != nil {
			die("--signature-base64 not valid base64: %v", err)
		}
		if err := verifyManifest(manifest, sig); err != nil {
			die("template signature rejected: %v", err)
		}
		// S5.4: enforce manifest's spec.minSudoLevel against the host's
		// current power_mode setting. Templates that need elevated
		// privileges must NOT install while Power Mode is locked — the
		// operator has to explicitly call `obachtctl system unlock-
		// power` first (which itself is a deliberate two-step flow).
		if level := extractMinSudoLevel(manifest); level == "power" {
			if err := r.assertPowerModeEnabled(ctx); err != nil {
				die("template requires power mode: %v", err)
			}
		}
	}

	var configRaw any
	runtimeKind := "container"
	if *configJSON != "" {
		if err := json.Unmarshal([]byte(*configJSON), &configRaw); err != nil {
			die("--config-json is not valid JSON: %v", err)
		}
	}

	// S6.5: when the api hands us the manifest bytes, materialise the
	// container.Spec right here. --config-json is then interpreted as
	// the user-supplied form values map (e.g. {"name":"hello"}). The
	// reconciler downstream stores whatever we pass under `config` as
	// instances.config_json and the docker driver consumes it.
	//
	// Rollout-fallback: when no manifest bytes are present (legacy
	// templates pre-S4) we keep the v0 behaviour and pass --config-json
	// through verbatim — it must already BE a container.Spec in that
	// case.
	if *manifestB64 != "" {
		manifestBytes, err := decodeB64(*manifestB64)
		if err != nil {
			die("--manifest-base64 not valid base64: %v", err)
		}
		userCfg := map[string]any{}
		if configRaw != nil {
			if m, ok := configRaw.(map[string]any); ok {
				userCfg = m
			} else {
				die("--config-json must be a JSON object when materialising from manifest")
			}
		}
		spec, err := materializeManifest(manifestBytes, userCfg, *iid, *tid)
		if err != nil {
			die("manifest materialise: %v", err)
		}
		if unresolved := findUnresolvedPlaceholders(spec.Config); len(unresolved) > 0 {
			// ${secret.X} placeholders are expected to survive
			// materialisation for both compose AND container runtimes
			// — the agent's reconciler substitutes them at apply time
			// using values from the per-instance secret store. ${cfg.X}
			// is also legal for compose (driver substitutes at apply).
			var real []string
			for _, u := range unresolved {
				if strings.HasPrefix(u, "secret.") {
					continue
				}
				if spec.Runtime == "compose" && strings.HasPrefix(u, "cfg.") {
					continue
				}
				real = append(real, u)
			}
			if len(real) > 0 {
				die("template refers to unset values: %s — provide them via --config-json", strings.Join(real, ", "))
			}
		}
		var asAny any
		if err := json.Unmarshal(spec.Config, &asAny); err != nil {
			die("materialise self-check: %v", err)
		}
		configRaw = asAny
		runtimeKind = spec.Runtime

		// Fall back to the manifest's metadata.version when the api
		// didn't pass --version explicitly. The api's snapshot
		// reconciler refuses to upsert empty versions (NOT NULL).
		if *version == "" {
			if mv := extractManifestVersion(manifestBytes); mv != "" {
				*version = mv
			}
		}
	}
	if *version == "" {
		// Last-resort fallback so the api/supabase upsert never sees
		// an empty string.
		*version = "unknown"
	}

	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodPost, "/v1/admin/instances", map[string]any{
		"id":            *iid,
		"template_id":   *tid,
		"runtime":       runtimeKind,
		"version":       *version,
		"desired_state": "installed",
		"config":        configRaw,
		"signed":        *manifestB64 != "",
	})
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

// ---------------------------------------------------------------------------
// service — list + control of admin-installed systemd units.
//
// Listing is read-only via the agent IPC (`GET /v1/admin/systemd-services`),
// no privileges required.
//
// Mutation actions (start/stop/restart/reload/enable/disable) shell out to
// `sudo -n /usr/bin/systemctl <verb> <unit>`. The sudoers snippet that
// makes those calls password-less is owned by `obacht-power-toggle` and is
// only present when Power Mode is enabled. We pre-flight Power Mode here
// so the user gets a clean error instead of a sudo failure when the gate
// is locked.
// ---------------------------------------------------------------------------

// validUnitName matches systemd unit names: alphanumerics, dot, dash,
// underscore, '@' (for templated units). We require a `.service` suffix
// so the api-side plan-builder can't trick us into touching timers,
// sockets, mounts, etc.
func isValidServiceUnitName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	if !strings.HasSuffix(name, ".service") {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '-', c == '_', c == '@':
		default:
			return false
		}
	}
	return true
}

// allowedServiceVerbs is the closed allow-list of systemctl actions we
// expose. Anything else (mask, reset-failed, edit, ...) is rejected.
var allowedServiceVerbs = map[string]bool{
	"start":   true,
	"stop":    true,
	"restart": true,
	"reload":  true,
	"enable":  true,
	"disable": true,
}

func (r *runtime) cmdService(ctx context.Context, args []string) {
	if len(args) == 0 {
		die("usage: obachtctl service <list|start|stop|restart|reload|enable|disable> [--name UNIT]")
	}
	verb := args[0]
	if verb == "list" {
		r.serviceList(ctx)
		return
	}
	if !allowedServiceVerbs[verb] {
		die("unknown service subcommand: %s", verb)
	}
	r.serviceControl(ctx, verb, args[1:])
}

func (r *runtime) serviceList(ctx context.Context) {
	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/admin/systemd-services", nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) serviceControl(ctx context.Context, verb string, args []string) {
	fs := flag.NewFlagSet("service "+verb, flag.ExitOnError)
	name := fs.String("name", "", "unit name, must end in .service (required)")
	_ = fs.Bool("json", true, "output JSON (default; only mode currently supported)")
	systemctlPath := fs.String("systemctl", "/usr/bin/systemctl", "path to systemctl (override for tests)")
	skipSudo := fs.Bool("skip-sudo", false, "invoke systemctl directly (for root / tests)")
	noPowerCheck := fs.Bool("skip-power-check", false, "bypass the Power Mode pre-flight (tests only)")
	_ = fs.Parse(args)
	if *name == "" {
		die("--name UNIT.service is required")
	}
	if !isValidServiceUnitName(*name) {
		die("invalid unit name %q: must match [a-zA-Z0-9._@-]+\\.service", *name)
	}

	if !*noPowerCheck {
		if err := r.assertPowerModeEnabled(ctx); err != nil {
			die("%v", err)
		}
	}

	cmdName := "sudo"
	cmdArgs := []string{"-n", *systemctlPath, verb, *name}
	if *skipSudo {
		cmdName = *systemctlPath
		cmdArgs = []string{verb, *name}
	}
	out, err := exec.CommandContext(ctx, cmdName, cmdArgs...).CombinedOutput()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	resp := map[string]any{
		"ok":        exitCode == 0,
		"verb":      verb,
		"unit":      *name,
		"exit_code": exitCode,
		"output":    string(out),
	}
	body, _ := json.Marshal(resp)
	if exitCode == 0 {
		emit(http.StatusOK, body)
	} else {
		emit(http.StatusInternalServerError, body)
	}
}

// verifyManifest builds the trust bundle (embedded keys + /etc/obacht/
// trust.d/*.pub) and checks the minisign signature. Returns nil on
// success, non-nil error otherwise.
func verifyManifest(manifest, sig []byte) error {
	entries := append([]trust.KeyEntry(nil), trust.EmbeddedKeys...)
	dirEntries, err := trust.LoadFromDir(trustDir())
	if err != nil {
		return fmt.Errorf("read trust dir %s: %w", trustDir(), err)
	}
	entries = append(entries, dirEntries...)
	bundle, err := trust.New(entries)
	if err != nil {
		return fmt.Errorf("build trust bundle: %w", err)
	}
	return bundle.Verify(manifest, sig)
}

// extractMinSudoLevel parses just enough of the manifest to find
// spec.minSudoLevel. We do not unmarshal into the full manifest type
// to keep this command independent of the obacht-template-spec/go
// module (and to be permissive if the manifest carries extra fields).
//
// Returns "" if the field is absent (which is treated the same as
// "none" by the caller). Returns "power" only if the manifest
// explicitly opts in.
func extractMinSudoLevel(manifest []byte) string {
	var probe struct {
		Spec struct {
			MinSudoLevel string `json:"minSudoLevel" yaml:"minSudoLevel"`
		} `json:"spec" yaml:"spec"`
	}
	if err := json.Unmarshal(manifest, &probe); err != nil {
		// The api always sends JSON; YAML manifests are converted
		// upstream. If JSON parsing fails we treat the manifest as
		// not opting into power-mode. Callers still validate the
		// signature, so a tampered field would have been rejected.
		return ""
	}
	return probe.Spec.MinSudoLevel
}

// extractManifestVersion pulls metadata.version out of the manifest as
// a fallback when the api doesn't pass --version explicitly. The agent
// stores instances.version and the api's snapshot reconciler refuses
// to upsert empty strings (supabase column is NOT NULL), so we always
// want SOMETHING here.
func extractManifestVersion(manifest []byte) string {
	var probe struct {
		Metadata struct {
			Version string `json:"version" yaml:"version"`
		} `json:"metadata" yaml:"metadata"`
	}
	if err := yaml.Unmarshal(manifest, &probe); err != nil {
		return ""
	}
	return probe.Metadata.Version
}

// assertPowerModeEnabled queries the agent's IPC /v1/system/status
// endpoint and returns nil if `power_mode == "enabled"`. Any other
// value (or any error reaching the endpoint) is fail-closed.
func (r *runtime) assertPowerModeEnabled(ctx context.Context) error {
	r.requireIPC()
	code, body, err := r.doIPC(ctx, http.MethodGet, "/v1/system/status", nil)
	if err != nil {
		return fmt.Errorf("query system status: %w", err)
	}
	if code/100 != 2 {
		return fmt.Errorf("system status returned HTTP %d", code)
	}
	var probe struct {
		PowerMode any `json:"power_mode"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return fmt.Errorf("parse system status: %w", err)
	}
	switch v := probe.PowerMode.(type) {
	case bool:
		if v {
			return nil
		}
	case string:
		if v == "true" || v == "enabled" {
			return nil
		}
	}
	return fmt.Errorf("power_mode is locked; run `obachtctl system unlock-power` first")
}

func (r *runtime) templateUninstall(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("template uninstall", flag.ExitOnError)
	iid := fs.String("instance", "", "instance id (required)")
	hard := fs.Bool("hard", false, "delete row outright")
	_ = fs.Bool("json", false, "output JSON (default)")
	_ = fs.Parse(args)
	if *iid == "" {
		die("--instance is required")
	}
	r.requireIPC()
	path := "/v1/admin/instances/" + *iid
	if *hard {
		path += "?hard=1"
	}
	code, body, err := r.doIPC(ctx, http.MethodDelete, path, nil)
	if err != nil {
		die("%v", err)
	}
	emit(code, body)
}

func (r *runtime) requireIPC() {
	if r.directMode() {
		die("this command requires the daemon (not available in --db mode)")
	}
}

// --- helpers ---

func readFileOrStdin(p string) ([]byte, error) {
	if p == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(p)
}

func emit(code int, body []byte) {
	if code >= 400 {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	os.Stdout.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		fmt.Println()
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "obachtctl: "+format+"\n", a...)
	os.Exit(1)
}

// decodeB64 accepts both standard and url-safe base64, with or
// without padding. The api could realistically emit either depending
// on which Node helper it uses, so we try both.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func usage(w *os.File) {
	fmt.Fprintln(w, "usage: obachtctl [--socket=PATH] [--db=PATH] <command>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  version                                  print CLI version")
	fmt.Fprintln(w, "  health                                   ping the agent daemon")
	fmt.Fprintln(w, "  reconcile trigger                        request an immediate reconcile pass")
	fmt.Fprintln(w, "  instance list                            list known instances (JSON)")
	fmt.Fprintln(w, "  instance upsert --id=ID --template=T [--runtime=container|system] [--state=installed|stopped|removed] [--version=V] [--config-file=PATH|-]")
	fmt.Fprintln(w, "  instance remove --id=ID [--hard]")
	fmt.Fprintln(w, "  instance secret --id=ID                  (re)issue per-instance IPC secret")
	fmt.Fprintln(w, "  domain list                              list domains and bindings (JSON)")
	fmt.Fprintln(w, "  domain claim --domain=FQDN               request a domain (will be ACME-issued)")
	fmt.Fprintln(w, "  domain unclaim --domain=FQDN             remove a domain")
	fmt.Fprintln(w, "  domain bind --domain=FQDN --instance=ID --service=NAME [--mode=root|path] [--path-prefix=/x]")
	fmt.Fprintln(w, "  domain unbind --domain=FQDN              remove ingress binding for a domain")
	fmt.Fprintln(w, "  domain service --instance=ID --service=NAME --target=TGT [--type=docker_dns|host_port]")
	fmt.Fprintln(w, "  ingress reload                           force a Caddy reload")
	fmt.Fprintln(w, "  audit tail [--n N]                       show recent audit entries (newest first)")
	fmt.Fprintln(w, "  system status                            show agent runtime + counters")
	fmt.Fprintln(w, "  service list                             list custom systemd services (JSON)")
	fmt.Fprintln(w, "  service start|stop|restart|reload|enable|disable --name=UNIT.service")
	fmt.Fprintln(w, "                                           control a systemd unit (requires Power Mode)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "with --db=PATH commands write directly to the SQLite SSOT (no daemon required).")
}
