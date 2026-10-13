package readiness

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/store"
)

// Probe cadence and thresholds (see docs in the task contract).
const (
	// startingInterval is how often a starting instance is probed.
	startingInterval = 5 * time.Second
	// requestTimeout bounds one HTTP probe.
	requestTimeout = 5 * time.Second
	// unhealthyAfter is how many consecutive failed steady-state probes it
	// takes to flip ready → unhealthy (one slow answer must not flap).
	unhealthyAfter = 3
	// steadyWorkers bounds the parallelism of the per-tick steady probes.
	steadyWorkers = 6
	// edgeNetwork is the docker network the agent's Caddy and every
	// routable container share; its IP is what a Linux host can reach.
	edgeNetwork = "obacht-edge"
)

// Target describes what to probe for one instance: its primary routable
// service. The reconciler builds it from the runtime spec.
type Target struct {
	InstanceID  string
	ServiceName string
	// ContainerName is the docker container serving the service
	// ("obacht-<id>" or the compose primary container). Empty for system
	// instances.
	ContainerName string
	// TargetPort is the port the service listens on inside the container
	// (or on the host for HostPort targets).
	TargetPort int
	// HostPort marks a system instance service (targetType host_port): the
	// app listens on 127.0.0.1:<TargetPort> on the device itself.
	HostPort bool
	Config   *Config
}

// startingRun identifies one starting goroutine so a run that was replaced
// by a later Begin never clears its successor's registration.
type startingRun struct{ cancel context.CancelFunc }

// Inspector is the slice of the docker driver the prober needs (container
// IP on the edge network + docker's own health status).
type Inspector interface {
	Inspect(ctx context.Context, name string) (map[string]any, error)
}

// Prober owns the readiness state machine for every instance on the device.
// Zero goroutines in steady state: a goroutine exists only while an
// instance is starting; settled instances are re-probed inline from the
// reconcile tick via RunSteady.
type Prober struct {
	st        *store.Store
	inspect   Inspector
	httpsPort int
	log       *slog.Logger
	notify    func()

	// Test hooks: interval between starting probes and an override for the
	// starting-phase timeout (zero = the target's config).
	interval        time.Duration
	timeoutOverride time.Duration

	mu       sync.Mutex
	active   map[string]*startingRun // instances with a starting goroutine
	failures map[string]int          // consecutive steady failures per instance
	ips      map[string]string       // cached edge-network IP per container name
}

// New returns a Prober. httpsPort is the device Caddy's TLS port
// (Ingress.HTTPSPort: 443 on Pis, 8443 on the Mac).
func New(st *store.Store, inspect Inspector, httpsPort int, log *slog.Logger) *Prober {
	if httpsPort == 0 {
		httpsPort = 443
	}
	if log == nil {
		log = slog.Default()
	}
	return &Prober{
		st:        st,
		inspect:   inspect,
		httpsPort: httpsPort,
		log:       log.With("component", "readiness"),
		interval:  startingInterval,
		active:    map[string]*startingRun{},
		failures:  map[string]int{},
		ips:       map[string]string{},
	}
}

// SetNotify registers the callback fired on every readiness transition (the
// reconciler's change notifier, so the syncer pushes a snapshot at once).
func (p *Prober) SetNotify(fn func()) { p.notify = fn }

// Active reports whether a starting goroutine currently owns the instance.
func (p *Prober) Active(instanceID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.active[instanceID]
	return ok
}

// Set records a readiness state for an instance, persisting it and firing
// the notifier only on a real transition. ready_at is set exactly when the
// state is ready. Shared by the prober and by the host-service hook sink.
func (p *Prober) Set(ctx context.Context, instanceID, state string) {
	inst, err := p.st.GetInstance(ctx, instanceID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			p.log.Warn("read instance", "instance", instanceID, "err", err)
		}
		return
	}
	if inst.ServiceReady == state {
		return
	}
	var readyAt time.Time
	if state == StateReady {
		readyAt = time.Now()
	}
	if err := p.st.SetServiceReady(ctx, instanceID, state, readyAt); err != nil {
		p.log.Warn("record service_ready", "instance", instanceID, "err", err)
		return
	}
	p.log.Info("readiness", "instance", instanceID, "from", inst.ServiceReady, "to", state)
	if p.notify != nil {
		p.notify()
	}
}

// Begin (re)starts the starting phase for an instance: state → starting, and
// one goroutine probes every 5 s until a probe passes (ready) or the
// configured timeout elapses (unhealthy). A goroutine already running for
// the instance is cancelled and replaced (container recreated, restarted).
func (p *Prober) Begin(t Target) {
	if t.InstanceID == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &startingRun{cancel: cancel}
	p.mu.Lock()
	if old, ok := p.active[t.InstanceID]; ok {
		old.cancel()
	}
	p.active[t.InstanceID] = run
	delete(p.failures, t.InstanceID)
	if t.ContainerName != "" {
		delete(p.ips, t.ContainerName) // a recreated container gets a new IP
	}
	p.mu.Unlock()

	p.Set(ctx, t.InstanceID, StateStarting)
	go p.runStarting(ctx, run, t)
}

// Forget drops every trace of an instance (stopped or removed): the
// starting goroutine is cancelled and the counters cleared. The store row is
// the caller's business (it is deleted on remove, reset on stop).
func (p *Prober) Forget(instanceID string, containerName string) {
	p.mu.Lock()
	if run, ok := p.active[instanceID]; ok {
		run.cancel()
		delete(p.active, instanceID)
	}
	delete(p.failures, instanceID)
	if containerName != "" {
		delete(p.ips, containerName)
	}
	p.mu.Unlock()
}

func (p *Prober) runStarting(ctx context.Context, run *startingRun, t Target) {
	defer func() {
		run.cancel()
		p.markDone(t.InstanceID, run)
	}()
	budget := t.Config.timeout()
	if p.timeoutOverride > 0 {
		budget = p.timeoutOverride
	}
	deadline := time.Now().Add(budget)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		ok, detail := p.probe(ctx, t)
		if ctx.Err() != nil {
			return
		}
		if ok {
			p.markDone(t.InstanceID, run)
			p.Set(context.Background(), t.InstanceID, StateReady)
			return
		}
		if time.Now().After(deadline) {
			p.log.Warn("readiness timeout", "instance", t.InstanceID, "last", detail, "after", budget)
			p.markDone(t.InstanceID, run)
			p.Set(context.Background(), t.InstanceID, StateUnhealthy)
			return
		}
		p.log.Debug("readiness not yet", "instance", t.InstanceID, "detail", detail)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// markDone removes the run's registration (only if it is still the current
// one) so the next tick treats the instance as settled.
func (p *Prober) markDone(instanceID string, run *startingRun) {
	p.mu.Lock()
	if cur, ok := p.active[instanceID]; ok && cur == run {
		delete(p.active, instanceID)
	}
	p.mu.Unlock()
}

// RunSteady re-probes settled instances (ready or unhealthy) once, in
// parallel with a bounded worker count, and applies the flap rules: an
// unhealthy instance is ready again on the first passing probe, a ready one
// becomes unhealthy only after three consecutive failures. Blocks for at
// most a few request timeouts, which is why the reconcile tick can call it
// inline.
func (p *Prober) RunSteady(ctx context.Context, targets []Target) {
	if len(targets) == 0 {
		return
	}
	// Collect the current states in one read so a goroutine that flipped
	// the instance meanwhile is respected.
	states := map[string]string{}
	if insts, err := p.st.ListInstances(ctx); err == nil {
		for _, i := range insts {
			states[i.ID] = i.ServiceReady
		}
	}
	sem := make(chan struct{}, steadyWorkers)
	var wg sync.WaitGroup
	for _, t := range targets {
		if p.Active(t.InstanceID) {
			continue // starting goroutine owns it
		}
		st := states[t.InstanceID]
		if st != StateReady && st != StateUnhealthy {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target, cur string) {
			defer wg.Done()
			defer func() { <-sem }()
			ok, detail := p.probe(ctx, t)
			if ctx.Err() != nil {
				return
			}
			p.mu.Lock()
			if ok {
				p.failures[t.InstanceID] = 0
			} else {
				p.failures[t.InstanceID]++
			}
			n := p.failures[t.InstanceID]
			p.mu.Unlock()
			switch {
			case ok && cur == StateUnhealthy:
				p.Set(ctx, t.InstanceID, StateReady)
			case !ok && cur == StateReady && n >= unhealthyAfter:
				p.log.Warn("readiness lost", "instance", t.InstanceID, "detail", detail, "failures", n)
				p.Set(ctx, t.InstanceID, StateUnhealthy)
			case !ok:
				p.log.Debug("readiness probe failed", "instance", t.InstanceID, "detail", detail, "failures", n)
			}
		}(t, st)
	}
	wg.Wait()
}

// probe runs one readiness check following the order of preference:
//
//  1. through the device's own Caddy when the instance has a domain
//     binding (what a visitor gets, including basic auth → 401 = answers);
//  2. Linux: straight at the container's IP on obacht-edge;
//  3. docker's own HEALTHCHECK when the image has one, else running =
//     ready (today's behaviour) — the Mac path, where containers live in a
//     VM the host cannot route to.
//
// System host_port services are probed at 127.0.0.1:<port>.
func (p *Prober) probe(ctx context.Context, t Target) (bool, string) {
	path := t.Config.path()

	if domain, prefix := p.binding(ctx, t); domain != "" {
		ok, transportErr, detail := p.probeViaCaddy(ctx, domain, joinPath(prefix, path), t.Config)
		if !transportErr {
			return ok, detail
		}
		// Caddy itself is unreachable from the agent (not running yet, or a
		// Mac where the VM's port is not on the host loopback). That says
		// nothing about the app — fall through to the direct checks.
		p.log.Debug("readiness: caddy unreachable, falling back", "instance", t.InstanceID, "detail", detail)
	}

	if t.HostPort {
		ok, _, detail := p.probeHTTP(ctx, fmt.Sprintf("http://127.0.0.1:%d%s", t.TargetPort, path), "", t.Config)
		return ok, detail
	}
	if t.ContainerName == "" || p.inspect == nil {
		return false, "no probe target"
	}

	insp, err := p.inspect.Inspect(ctx, t.ContainerName)
	if err != nil {
		return false, "inspect: " + err.Error()
	}
	if insp == nil {
		return false, "container not found"
	}
	state, _ := insp["State"].(map[string]any)
	if running, _ := state["Running"].(bool); !running {
		return false, "container not running"
	}

	if runtime.GOOS == "linux" && t.TargetPort > 0 {
		if ip := p.containerIP(t.ContainerName, insp); ip != "" {
			ok, _, detail := p.probeHTTP(ctx, fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, strconv.Itoa(t.TargetPort)), path), "", t.Config)
			return ok, detail
		}
	}

	// Docker health, if the image declares a HEALTHCHECK.
	if health, ok := state["Health"].(map[string]any); ok {
		switch status, _ := health["Status"].(string); status {
		case "healthy":
			return true, "docker health: healthy"
		case "unhealthy":
			return false, "docker health: unhealthy"
		case "starting":
			return false, "docker health: starting"
		}
	}
	return true, "running (no health check)"
}

// binding returns the domain (and path prefix) bound to the target's
// service, or "" when the instance has no domain.
func (p *Prober) binding(ctx context.Context, t Target) (string, string) {
	binds, err := p.st.ListBindings(ctx)
	if err != nil {
		return "", ""
	}
	var fallback *store.IngressBinding
	for i := range binds {
		b := binds[i]
		if b.InstanceID != t.InstanceID {
			continue
		}
		if b.ServiceName == t.ServiceName {
			return b.Domain, prefixOf(b)
		}
		if fallback == nil {
			fallback = &binds[i]
		}
	}
	if fallback != nil {
		return fallback.Domain, prefixOf(*fallback)
	}
	return "", ""
}

func prefixOf(b store.IngressBinding) string {
	if b.Mode == "path" {
		return b.PathPrefix
	}
	return ""
}

// containerIP returns the container's address on the edge network (cached
// per container name; cleared when the container is recreated).
func (p *Prober) containerIP(name string, insp map[string]any) string {
	p.mu.Lock()
	if ip, ok := p.ips[name]; ok {
		p.mu.Unlock()
		return ip
	}
	p.mu.Unlock()
	ns, _ := insp["NetworkSettings"].(map[string]any)
	nets, _ := ns["Networks"].(map[string]any)
	ip := ""
	if edge, ok := nets[edgeNetwork].(map[string]any); ok {
		ip, _ = edge["IPAddress"].(string)
	}
	if ip == "" {
		for _, n := range nets {
			if m, ok := n.(map[string]any); ok {
				if v, _ := m["IPAddress"].(string); v != "" {
					ip = v
					break
				}
			}
		}
	}
	if ip != "" {
		p.mu.Lock()
		p.ips[name] = ip
		p.mu.Unlock()
	}
	return ip
}

// probeViaCaddy requests https://127.0.0.1:<httpsPort><path> with SNI and
// Host set to the bound domain. The cert may still be pending (or be
// Caddy's internal one), so verification is skipped: this measures whether
// the app answers, not whether the domain is served correctly.
func (p *Prober) probeViaCaddy(ctx context.Context, domain, path string, cfg *Config) (ok, transportErr bool, detail string) {
	url := fmt.Sprintf("https://127.0.0.1:%d%s", p.httpsPort, path)
	return p.probeHTTP(ctx, url, domain, cfg)
}

// probeHTTP issues one GET with the 5 s budget, following no redirects.
// transportErr is true when no HTTP response came back at all (dial, TLS,
// timeout) as opposed to an unaccepted status.
func (p *Prober) probeHTTP(ctx context.Context, url, serverName string, cfg *Config) (ok, transportErr bool, detail string) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: requestTimeout}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // see probeViaCaddy
			ServerName:         serverName,
		},
		TLSHandshakeTimeout: requestTimeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, true, err.Error()
	}
	if serverName != "" {
		req.Host = serverName
	}
	req.Header.Set("User-Agent", "obacht-agent-readiness/1")
	resp, err := client.Do(req)
	if err != nil {
		return false, true, shortErr(err)
	}
	defer resp.Body.Close()
	detail = fmt.Sprintf("%s -> %d", url, resp.StatusCode)
	return cfg.accepts(resp.StatusCode), false, detail
}

// shortErr trims Go's verbose url.Error prefix for log lines.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i < len(s)-2 {
		return s[i+2:]
	}
	return s
}
