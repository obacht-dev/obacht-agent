// obachtctl is the device-local control CLI. It speaks to the agent daemon
// over its unix-socket IPC by default; falls back to direct SQLite access
// when --db is given (useful for tests where the daemon is not running).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

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
	case "domain":
		rt.cmdDomain(ctx, args[1:])
	case "ingress":
		rt.cmdIngress(ctx, args[1:])
	case "reconcile":
		rt.cmdReconcile(ctx, args[1:])
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
		die("usage: obachtctl instance <list|upsert|remove|secret>")
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
		_ = fs.Parse(args[1:])
		if *domain == "" || *instID == "" || *svc == "" {
			die("--domain, --instance, --service required")
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
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "with --db=PATH commands write directly to the SQLite SSOT (no daemon required).")
}
