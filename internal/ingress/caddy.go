// Package ingress manages Caddy as the device-local edge proxy.
//
// Responsibilities:
//   - Ensure a shared docker network (`obacht-edge`) exists so the Caddy
//     container can reach template containers by name.
//   - Run a single Caddy 2 container with persistent data/config volumes.
//   - Generate the Caddyfile from the SQLite SSOT (domains + ingress_bindings
//     + instance_services) and reload Caddy in place.
//   - Drive the per-domain state machine: pending → claiming → ready → bound
//     (observed_status), reflecting what Caddy has actually achieved.
//
// We intentionally manage Caddy via a container instead of embedding it as a
// Go library: it lets us version Caddy independently from the agent and
// keeps the agent binary small.
package ingress

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/runtime/container"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// ContainerName is the docker container name we use for Caddy.
const ContainerName = "obacht-caddy"

// caddyDataVolume is the named docker volume holding Caddy's /data (ACME
// certs + state) in containerized mode (Mac VM), where host bind-mounts
// aren't reachable. Persists across container restarts + VM reboots.
const caddyDataVolume = "obacht-caddy-data"

// domainRe matches a syntactically valid DNS hostname. Each domain is rendered
// as an UNQUOTED Caddy site-block label (`<domain> {`), so a value containing
// whitespace, braces or newlines could inject arbitrary Caddy directives.
// Reject anything that is not a plain hostname before it reaches the Caddyfile.
var domainRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// isValidDomain reports whether d is a safe DNS hostname to render into the
// Caddyfile (total length <= 253, only [A-Za-z0-9.-], valid label structure).
func isValidDomain(d string) bool {
	return len(d) <= 253 && domainRe.MatchString(d)
}

// Manager owns the Caddy lifecycle and Caddyfile generation.
type Manager struct {
	docker  *container.Driver
	store   *store.Store
	cfg     config.IngressConfig
	paths   config.PathsConfig
	log     *slog.Logger

	mu       sync.Mutex
	lastHash string

	ensureMu sync.Mutex
}

// New constructs a Manager. Call Bootstrap once at startup before any Apply.
func New(docker *container.Driver, st *store.Store, cfg config.IngressConfig, paths config.PathsConfig, log *slog.Logger) *Manager {
	return &Manager{docker: docker, store: st, cfg: cfg, paths: paths, log: log}
}

// Bootstrap ensures the docker network and Caddy container exist with an
// initial (possibly empty) Caddyfile. Safe to call multiple times.
func (m *Manager) Bootstrap(ctx context.Context) error {
	if m.cfg.Disabled {
		m.log.Info("ingress disabled by config; skipping bootstrap")
		return nil
	}
	if err := m.docker.EnsureNetwork(ctx, m.cfg.Network); err != nil {
		return fmt.Errorf("ensure network: %w", err)
	}
	if err := m.ensureDirs(); err != nil {
		return err
	}
	caddyfile, _, err := m.renderCaddyfile(ctx)
	if err != nil {
		return fmt.Errorf("render initial caddyfile: %w", err)
	}
	if err := m.writeCaddyfile(caddyfile); err != nil {
		return err
	}
	if err := m.ensureCaddyContainer(ctx); err != nil {
		return fmt.Errorf("ensure caddy container: %w", err)
	}
	m.log.Info("ingress bootstrap complete", "network", m.cfg.Network, "image", m.cfg.Image)
	return nil
}

// Apply re-renders the Caddyfile, writes it to disk, and reloads Caddy if
// anything changed. It also updates each domain's observed_status based on
// whether it has a binding (bound) or not (ready).
func (m *Manager) Apply(ctx context.Context) error {
	if m.cfg.Disabled {
		return nil
	}
	caddyfile, summary, err := m.renderCaddyfile(ctx)
	if err != nil {
		return fmt.Errorf("render caddyfile: %w", err)
	}
	hash := sha256Hex(caddyfile)

	m.mu.Lock()
	changed := hash != m.lastHash
	m.mu.Unlock()

	if changed {
		if err := m.writeCaddyfile(caddyfile); err != nil {
			return err
		}
		// Make sure Caddy is up before we ask it to reload.
		if err := m.ensureCaddyContainer(ctx); err != nil {
			return err
		}
		// Containerized: push the updated Caddyfile into the container
		// before the reload reads it (no bind-mount to pick it up). Cheap +
		// idempotent; a fresh container was already seeded at create.
		if m.cfg.Containerized {
			if err := m.copyCaddyfileToContainer(ctx); err != nil {
				return fmt.Errorf("copy caddyfile: %w", err)
			}
		}
		if err := m.reloadCaddy(ctx); err != nil {
			return fmt.Errorf("reload caddy: %w", err)
		}
		m.mu.Lock()
		m.lastHash = hash
		m.mu.Unlock()
		m.log.Info("caddyfile reloaded", "hash", hash[:12], "domains", summary.totalDomains, "bound", summary.bound)
	}

	// Reflect observed status into the SSOT regardless of whether the
	// Caddyfile changed: cert state can flip without the file changing.
	for d, s := range summary.observed {
		if err := m.store.SetDomainObserved(ctx, d, s, ""); err != nil {
			m.log.Warn("set domain observed", "domain", d, "err", err)
		}
	}
	// Refresh cert metadata (NotAfter + Issuer) from the on-disk PEM. Pure
	// telemetry — the platform only learns expiry/issuer, never the key.
	// Caddy writes certs as root inside its container with mode 0600, so
	// first widen .crt perms (keys stay 0600) so the agent's obacht user
	// can read them. Best-effort: a chmod failure shouldn't block reload.
	if err := m.chmodCertsForAgentRead(ctx); err != nil {
		m.log.Debug("chmod certs", "err", err)
	}
	if err := m.ScanCerts(ctx); err != nil {
		m.log.Debug("scan certs", "err", err)
	}
	return nil
}

// Reload forces Caddy to reload (no-op render diff). Useful after manual edits.
func (m *Manager) Reload(ctx context.Context) error {
	if m.cfg.Disabled {
		return nil
	}
	if err := m.ensureCaddyContainer(ctx); err != nil {
		return err
	}
	if m.cfg.Containerized {
		if err := m.copyCaddyfileToContainer(ctx); err != nil {
			return fmt.Errorf("copy caddyfile: %w", err)
		}
	}
	return m.reloadCaddy(ctx)
}

// --- helpers ---

func (m *Manager) ensureDirs() error {
	for _, p := range []string{m.paths.CaddyData, m.paths.CaddyConfig} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", p, err)
		}
	}
	return nil
}

func (m *Manager) caddyfilePath() string { return filepath.Join(m.paths.CaddyConfig, "Caddyfile") }

func (m *Manager) writeCaddyfile(body string) error {
	// Always stage to the host path: on the Pi this IS the bind-mounted
	// file; in containerized mode it's the source copyCaddyfileToContainer
	// streams into the VM container.
	return os.WriteFile(m.caddyfilePath(), []byte(body), 0o644)
}

// copyCaddyfileToContainer streams the staged Caddyfile into the Caddy
// container at /etc/caddy/Caddyfile via the docker archive API. Used in
// containerized mode (Mac VM) where the agent's host path isn't a valid
// bind source for the VM's dockerd. Works on created-but-not-started
// containers, so it can seed the file before the first start.
func (m *Manager) copyCaddyfileToContainer(ctx context.Context) error {
	data, err := os.ReadFile(m.caddyfilePath())
	if err != nil {
		return fmt.Errorf("read staged caddyfile: %w", err)
	}
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "Caddyfile",
		Mode: 0o644,
		Size: int64(len(data)),
	}); err != nil {
		return fmt.Errorf("tar header: %w", err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("tar write: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://docker/v1.43/containers/"+ContainerName+"/archive?path=/etc/caddy",
		bytes.NewReader(tarBuf.Bytes()))
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := m.docker.HTTP().Do(req)
	if err != nil {
		return fmt.Errorf("put archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("put archive %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

type renderSummary struct {
	totalDomains int
	bound        int
	observed     map[string]string // domain → observed_status to write back
}

// renderCaddyfile builds the Caddyfile body from current SSOT. It returns
// the rendered body plus a summary the caller uses to update observed state.
//
// Layout:
//
//	{
//	    admin 0.0.0.0:2019
//	}
//
//	# Default site for ready+unbound domains.
//	example.com {
//	    respond "obacht: domain ready, no app bound yet" 200
//	}
//
//	# Bound site.
//	app.example.com {
//	    reverse_proxy obacht-myapp:8080
//	}
func (m *Manager) renderCaddyfile(ctx context.Context) (string, renderSummary, error) {
	domains, err := m.store.ListDomains(ctx)
	if err != nil {
		return "", renderSummary{}, err
	}
	bindings, err := m.store.ListBindings(ctx)
	if err != nil {
		return "", renderSummary{}, err
	}
	services, err := m.store.ListInstanceServices(ctx)
	if err != nil {
		return "", renderSummary{}, err
	}

	bindByDomain := map[string]store.IngressBinding{}
	for _, b := range bindings {
		bindByDomain[b.Domain] = b
	}
	svcKey := func(inst, name string) string { return inst + "/" + name }
	svcMap := map[string]store.InstanceService{}
	for _, s := range services {
		svcMap[svcKey(s.InstanceID, s.ServiceName)] = s
	}

	httpPort, httpsPort := m.httpPort(), m.httpsPort()

	var b strings.Builder
	b.WriteString("# Generated by obacht-agent. Do not edit by hand.\n")
	b.WriteString("{\n\tadmin 0.0.0.0:2019\n")
	// Non-default ports (Mac VM: 8080/8443) must be declared globally so
	// Caddy's auto-HTTPS + ACME (TLS-ALPN-01) use the port the public 443
	// traffic actually arrives on (proxy → forwarder → VM Caddy).
	if httpPort != 80 {
		fmt.Fprintf(&b, "\thttp_port %d\n", httpPort)
	}
	if httpsPort != 443 {
		fmt.Fprintf(&b, "\thttps_port %d\n", httpsPort)
	}
	b.WriteString("}\n\n")

	summary := renderSummary{observed: map[string]string{}}

	// Stable order makes the hash stable.
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })

	for _, d := range domains {
		if d.DesiredStatus == store.DomainStatusRemoved {
			summary.observed[d.Domain] = store.DomainStatusRemoved
			continue
		}
		// Defense in depth: never render a domain that is not a plain DNS
		// hostname — it would otherwise be emitted as an unquoted Caddy site
		// label and could inject directives (SEC-12).
		if !isValidDomain(d.Domain) {
			m.log.Warn("skipping domain with invalid name", "domain", d.Domain)
			summary.observed[d.Domain] = store.DomainStatusError
			continue
		}
		summary.totalDomains++
		bind, hasBinding := bindByDomain[d.Domain]

		fmt.Fprintf(&b, "%s {\n", d.Domain)
		if hasBinding {
			var (
				upstream string
				upErr    error
			)
			if bind.LocalPort > 0 {
				// Local-port reverse proxy: target a host port (a service the
				// user runs directly on the Pi, outside obacht's container
				// runtime). Caddy is itself in a container, so we go via the
				// docker host gateway alias.
				upstream = fmt.Sprintf("host.docker.internal:%d", bind.LocalPort)
			} else {
				svc, ok := svcMap[svcKey(bind.InstanceID, bind.ServiceName)]
				if !ok {
					// Binding points at a missing service — fall back to a
					// helpful 503 so we still get a cert and a clear error.
					fmt.Fprintf(&b, "\trespond \"obacht: binding %s/%s has no registered service yet\" 503\n",
						bind.InstanceID, bind.ServiceName)
					summary.observed[d.Domain] = store.DomainStatusReady
					b.WriteString("}\n\n")
					continue
				}
				upstream, upErr = upstreamFor(svc, bind.InstanceID)
			}
			if upErr != nil {
				fmt.Fprintf(&b, "\trespond \"obacht: %s\" 503\n", escape(upErr.Error()))
				summary.observed[d.Domain] = store.DomainStatusReady
			} else {
				if bind.Mode == "path" && bind.PathPrefix != "" {
					fmt.Fprintf(&b, "\thandle %s* {\n\t\treverse_proxy %s\n\t}\n", bind.PathPrefix, upstream)
				} else {
					fmt.Fprintf(&b, "\treverse_proxy %s\n", upstream)
				}
				summary.bound++
				summary.observed[d.Domain] = store.DomainStatusBound
			}
		} else {
			b.WriteString("\trespond \"obacht: domain ready, no app bound yet\" 200\n")
			summary.observed[d.Domain] = store.DomainStatusReady
		}
		b.WriteString("}\n\n")
	}

	if summary.totalDomains == 0 {
		// Caddy needs *something* to listen on or it will exit. A loopback
		// admin-only listener is enough.
		fmt.Fprintf(&b, ":%d {\n\trespond \"obacht-agent: no domains configured\" 200\n}\n", httpPort)
	}
	return b.String(), summary, nil
}

// httpPort / httpsPort return the configured Caddy ports, defaulting to the
// privileged 80/443 (Pi) when unset.
func (m *Manager) httpPort() int {
	if m.cfg.HTTPPort != 0 {
		return m.cfg.HTTPPort
	}
	return 80
}

func (m *Manager) httpsPort() int {
	if m.cfg.HTTPSPort != 0 {
		return m.cfg.HTTPSPort
	}
	return 443
}

// upstreamFor returns the Caddy reverse_proxy target for a service.
func upstreamFor(svc store.InstanceService, instanceID string) (string, error) {
	switch svc.TargetType {
	case "host_port":
		// host_port targets like "127.0.0.1:8080" must be reached through the
		// docker host bridge.
		hp := svc.Target
		if strings.HasPrefix(hp, "127.0.0.1:") || strings.HasPrefix(hp, "localhost:") {
			parts := strings.SplitN(hp, ":", 2)
			if len(parts) == 2 {
				return "host.docker.internal:" + parts[1], nil
			}
		}
		return hp, nil
	case "docker_dns":
		// Caller should set Target to "containerName:port" — we resolve
		// container DNS automatically inside the obacht-edge network.
		return svc.Target, nil
	case "unix_socket":
		return "", fmt.Errorf("unix_socket target not supported by ingress (instance %s)", instanceID)
	default:
		return "", fmt.Errorf("unknown target_type %q for instance %s", svc.TargetType, instanceID)
	}
}

// hasHostGatewayExtraHost returns true if the inspected container already
// carries the `host.docker.internal:host-gateway` mapping we need to reach
// host-port reverse-proxy targets from inside the Caddy container.
func hasHostGatewayExtraHost(insp map[string]any) bool {
	hc, _ := insp["HostConfig"].(map[string]any)
	if hc == nil {
		return false
	}
	hosts, _ := hc["ExtraHosts"].([]any)
	for _, h := range hosts {
		if s, _ := h.(string); strings.HasPrefix(s, "host.docker.internal:") {
			return true
		}
	}
	return false
}

func (m *Manager) ensureCaddyContainer(ctx context.Context) error {
	// Serialize so concurrent Bootstrap + Apply can't both try to create.
	m.ensureMu.Lock()
	defer m.ensureMu.Unlock()

	// Try to start an existing container if it's stopped.
	insp, err := m.docker.Inspect(ctx, ContainerName)
	if err != nil {
		return err
	}
	if insp != nil {
		state, _ := insp["State"].(map[string]any)
		running, _ := state["Running"].(bool)
		if running {
			// Detect config drift from older agent versions and recreate if
			// the running container is missing settings we now require.
			if !hasHostGatewayExtraHost(insp) {
				m.log.Info("recreating caddy container to apply host-gateway extra host")
				if err := m.removeCaddyContainer(ctx); err != nil {
					return fmt.Errorf("remove drifted caddy: %w", err)
				}
			} else {
				// Make sure it is on the obacht-edge network.
				if err := m.docker.ConnectContainerToNetwork(ctx, ContainerName, m.cfg.Network); err != nil {
					m.log.Warn("connect caddy to network", "err", err)
				}
				return nil
			}
		} else {
			// Container exists but isn't running — easiest to recreate.
			if err := m.removeCaddyContainer(ctx); err != nil {
				return fmt.Errorf("remove stopped caddy: %w", err)
			}
		}
	}
	if err := m.docker.PullImage(ctx, m.cfg.Image); err != nil {
		return err
	}
	if err := m.createCaddyContainer(ctx); err != nil {
		// Conflict (409) means another caller created it concurrently or a
		// stale container with the same name exists. Try to remove + recreate
		// once.
		if strings.Contains(err.Error(), "create caddy 409") {
			m.log.Warn("caddy create conflict; removing leftover and retrying", "err", err)
			if rmErr := m.removeCaddyContainer(ctx); rmErr != nil {
				return fmt.Errorf("remove conflicting caddy: %w", rmErr)
			}
			if err := m.createCaddyContainer(ctx); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	if err := m.docker.ConnectContainerToNetwork(ctx, ContainerName, m.cfg.Network); err != nil {
		m.log.Warn("connect caddy to network", "err", err)
	}
	return nil
}

func (m *Manager) removeCaddyContainer(ctx context.Context) error {
	body, _ := json.Marshal(struct{}{})
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		"http://docker/v1.43/containers/"+ContainerName+"?force=true&v=false", bytes.NewReader(body))
	resp, err := m.docker.HTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 || resp.StatusCode == 404 {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("delete caddy %d: %s", resp.StatusCode, string(raw))
}

func (m *Manager) createCaddyContainer(ctx context.Context) error {
	httpPort, httpsPort := m.httpPort(), m.httpsPort()
	httpTCP := fmt.Sprintf("%d/tcp", httpPort)
	httpsTCP := fmt.Sprintf("%d/tcp", httpsPort)

	hostConfig := map[string]any{
		// Resolve host.docker.internal to the docker bridge gateway so
		// "local-port" reverse-proxy bindings (and host_port services)
		// can reach services running directly on the host/VM.
		"ExtraHosts": []string{"host.docker.internal:host-gateway"},
		"PortBindings": map[string][]map[string]string{
			httpTCP:  {{"HostIp": "0.0.0.0", "HostPort": strconv.Itoa(httpPort)}},
			httpsTCP: {{"HostIp": "0.0.0.0", "HostPort": strconv.Itoa(httpsPort)}},
		},
		"NetworkMode":   m.cfg.Network,
		"RestartPolicy": map[string]string{"Name": "unless-stopped"},
	}

	// Containerized (Mac VM): the agent's host paths aren't visible to the
	// VM's dockerd, so bind-mounts don't work. Keep /data in a named volume
	// (certs persist in the VM across restarts) and deliver the Caddyfile
	// via the docker archive API after create (copyCaddyfileToContainer).
	// Pi: bind-mount the host data + config dirs as before.
	if m.cfg.Containerized {
		hostConfig["Binds"] = []string{caddyDataVolume + ":/data:rw"}
	} else {
		hostConfig["Binds"] = []string{
			m.paths.CaddyData + ":/data:rw",
			m.paths.CaddyConfig + ":/etc/caddy:rw",
		}
	}

	body := map[string]any{
		"Image": m.cfg.Image,
		"Cmd":   []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
		"Labels": map[string]string{
			"obacht.managed": "1",
			"obacht.role":    "ingress",
		},
		"ExposedPorts": map[string]struct{}{
			httpTCP:  {},
			httpsTCP: {},
		},
		"HostConfig": hostConfig,
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/containers/create?name="+ContainerName, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.docker.HTTP().Do(req)
	if err != nil {
		return fmt.Errorf("create caddy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create caddy %d: %s", resp.StatusCode, string(raw))
	}

	// Containerized: the /etc/caddy bind is gone, so the freshly-created
	// container has no Caddyfile and `caddy run --config` would exit. Stream
	// the current Caddyfile in via the archive API BEFORE starting.
	if m.cfg.Containerized {
		if err := m.copyCaddyfileToContainer(ctx); err != nil {
			return fmt.Errorf("seed caddyfile: %w", err)
		}
	}

	startReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/containers/"+ContainerName+"/start", nil)
	sresp, err := m.docker.HTTP().Do(startReq)
	if err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != 204 && sresp.StatusCode != 304 {
		raw, _ := io.ReadAll(sresp.Body)
		return fmt.Errorf("start caddy %d: %s", sresp.StatusCode, string(raw))
	}
	// Give Caddy a moment to spin up before any reload.
	time.Sleep(500 * time.Millisecond)
	return nil
}

// reloadCaddy POSTs the on-disk Caddyfile to Caddy's admin API on the
// container. We exec `caddy reload` inside the container so we do not have
// to expose the admin port to the host.
func (m *Manager) reloadCaddy(ctx context.Context) error {
	// Use docker exec: POST /containers/{id}/exec then /exec/{id}/start.
	body, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          []string{"caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/containers/"+ContainerName+"/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.docker.HTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("exec create %d: %s", resp.StatusCode, string(raw))
	}
	var er struct{ Id string }
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return err
	}
	startBody, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	sReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/exec/"+er.Id+"/start", bytes.NewReader(startBody))
	sReq.Header.Set("Content-Type", "application/json")
	sResp, err := m.docker.HTTP().Do(sReq)
	if err != nil {
		return err
	}
	defer sResp.Body.Close()
	out, _ := io.ReadAll(sResp.Body)

	// Check exit code.
	insReq, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.43/exec/"+er.Id+"/json", nil)
	iResp, err := m.docker.HTTP().Do(insReq)
	if err != nil {
		return err
	}
	defer iResp.Body.Close()
	var ins struct{ ExitCode int }
	_ = json.NewDecoder(iResp.Body).Decode(&ins)
	if ins.ExitCode != 0 {
		return fmt.Errorf("caddy reload exit=%d output=%s", ins.ExitCode, sanitize(out))
	}
	return nil
}

// chmodCertsForAgentRead makes Caddy-issued .crt files world-readable so
// the agent (running as the unprivileged `obacht` user) can parse them
// in ScanCerts. Caddy inside the container runs as root and writes
// /data/caddy/certificates/<acme>/<dom>/<dom>.crt with mode 0600 owned
// by root, which is unreadable from the host. We deliberately leave
// the .key files untouched (still 0600 root) since the agent never
// needs them — only the cert metadata (NotAfter, Issuer).
//
// Runs as an exec into the caddy container so we don't need sudo on
// the host. Idempotent and cheap (chmod no-op if already correct).
func (m *Manager) chmodCertsForAgentRead(ctx context.Context) error {
	if m.cfg.Containerized {
		// Pointless in containerized mode: the host agent can't reach the
		// VM's named volume regardless of in-container permissions.
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd": []string{"sh", "-c",
			// Make /data/caddy and /data/caddy/certificates traversable by
			// the host-side obacht user (other+rx on directories, other+r on
			// .crt files). We must also fix the parent /data/caddy dir itself
			// which Caddy creates as 0700 root — without o+x on that parent
			// the host obacht user can't descend into certificates/ at all.
			"chmod o+rx /data /data/caddy 2>/dev/null; " +
				"if [ -d /data/caddy/certificates ]; then " +
				"find /data/caddy/certificates -type d -exec chmod o+rx {} + ; " +
				"find /data/caddy/certificates -name '*.crt' -exec chmod o+r {} + ; " +
				"fi",
		},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/containers/"+ContainerName+"/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.docker.HTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("exec create %d: %s", resp.StatusCode, string(raw))
	}
	var er struct{ Id string }
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return err
	}
	startBody, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	sReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/v1.43/exec/"+er.Id+"/start", bytes.NewReader(startBody))
	sReq.Header.Set("Content-Type", "application/json")
	sResp, err := m.docker.HTTP().Do(sReq)
	if err != nil {
		return err
	}
	defer sResp.Body.Close()
	_, _ = io.ReadAll(sResp.Body)
	return nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// sanitize strips docker exec stream multiplexing prefix bytes so log output
// stays readable. Best-effort.
func sanitize(b []byte) string {
	s := string(b)
	// docker exec streams have an 8-byte header per chunk in TTY=false mode
	// (we set TTY=false above). For our purposes a printable filter is enough.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 32 && c < 127 {
			out = append(out, c)
		} else if c == '\n' {
			out = append(out, '\n')
		}
	}
	return strings.TrimSpace(string(out))
}
