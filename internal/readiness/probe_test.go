package readiness

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/store"
)

func TestConfigValidateAndAccepts(t *testing.T) {
	var nilCfg *Config
	if err := nilCfg.Validate(); err != nil {
		t.Fatalf("nil config must be valid: %v", err)
	}
	good := []Config{{}, {Path: "/health"}, {ExpectStatus: []int{200, 404}}, {TimeoutSeconds: 10}, {TimeoutSeconds: 1800}}
	for _, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("valid config rejected %+v: %v", c, err)
		}
	}
	bad := []Config{{Path: "health"}, {Path: "/x://y"}, {Path: "http://x/"}, {Path: "/a b"}, {ExpectStatus: []int{99}}, {ExpectStatus: []int{600}}, {TimeoutSeconds: 9}, {TimeoutSeconds: 1801}}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("invalid config accepted: %+v", c)
		}
	}
	// Defaults: 2xx/3xx + 401/403 pass, 404/5xx do not.
	for s, want := range map[int]bool{200: true, 204: true, 302: true, 399: true, 401: true, 403: true, 404: false, 500: false, 502: false, 100: false} {
		if got := nilCfg.accepts(s); got != want {
			t.Errorf("default accepts(%d) = %v, want %v", s, got, want)
		}
	}
	c := &Config{ExpectStatus: []int{404}}
	if !c.accepts(404) || c.accepts(200) {
		t.Error("expectStatus must replace the default set")
	}
	if nilCfg.path() != "/" || nilCfg.timeout() != 300*time.Second {
		t.Error("defaults")
	}
	if joinPath("/app/", "/health") != "/app/health" || joinPath("", "/") != "/" || joinPath("/app", "/") != "/app/" {
		t.Error("joinPath")
	}
}

// stubInspector plays dockerd's /containers/<name>/json.
type stubInspector struct {
	mu      sync.Mutex
	running bool
	health  string // "" = no HEALTHCHECK
	ip      string
	missing bool
}

func (s *stubInspector) Inspect(_ context.Context, _ string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.missing {
		return nil, nil
	}
	state := map[string]any{"Running": s.running}
	if s.health != "" {
		state["Health"] = map[string]any{"Status": s.health}
	}
	return map[string]any{
		"State": state,
		"NetworkSettings": map[string]any{"Networks": map[string]any{
			edgeNetwork: map[string]any{"IPAddress": s.ip},
		}},
	}, nil
}

func newTestProber(t *testing.T, insp Inspector, httpsPort int) (*Prober, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p := New(st, insp, httpsPort, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.interval = 30 * time.Millisecond
	return p, st
}

func seedInstance(t *testing.T, st *store.Store, id string) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertInstance(ctx, store.Instance{ID: id, TemplateID: "tpl", Runtime: store.RuntimeContainer, DesiredState: store.DesiredInstalled}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetObservedState(ctx, id, "installed", ""); err != nil {
		t.Fatal(err)
	}
}

func bindDomain(t *testing.T, st *store.Store, domain, id, svc, mode, prefix string) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertDomain(ctx, domain, store.DomainStatusReady); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertBinding(ctx, store.IngressBinding{Domain: domain, InstanceID: id, ServiceName: svc, Mode: mode, PathPrefix: prefix}); err != nil {
		t.Fatal(err)
	}
}

func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(ps)
	return p
}

func waitState(t *testing.T, st *store.Store, id, want string) store.Instance {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		inst, err := st.GetInstance(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if inst.ServiceReady == want {
			return *inst
		}
		if time.Now().After(deadline) {
			t.Fatalf("service_ready = %q, want %q", inst.ServiceReady, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Domain path: the probe goes to https://127.0.0.1:<httpsPort> with the
// bound domain as SNI/Host and the binding's path prefix in front of the
// configured readiness path; a 200 makes the instance ready.
func TestBegin_ViaCaddyBecomesReady(t *testing.T) {
	var gotHost, gotPath, gotSNI atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		gotPath.Store(r.URL.Path)
		if r.TLS != nil {
			gotSNI.Store(r.TLS.ServerName)
		}
		w.WriteHeader(200)
	}))
	srv.StartTLS()
	defer srv.Close()

	insp := &stubInspector{running: true}
	p, st := newTestProber(t, insp, portOf(t, srv))
	seedInstance(t, st, "i1")
	bindDomain(t, st, "app.example.com", "i1", "web", "path", "/app")

	var notified atomic.Int32
	p.SetNotify(func() { notified.Add(1) })
	p.Begin(Target{InstanceID: "i1", ServiceName: "web", ContainerName: "obacht-i1", TargetPort: 8080, Config: &Config{Path: "/health"}})
	inst := waitState(t, st, "i1", StateReady)
	if inst.ReadyAt.IsZero() {
		t.Fatal("ready_at must be set when ready")
	}
	if gotHost.Load() != "app.example.com" || gotSNI.Load() != "app.example.com" {
		t.Fatalf("host/sni: %v / %v", gotHost.Load(), gotSNI.Load())
	}
	if gotPath.Load() != "/app/health" {
		t.Fatalf("path: %v", gotPath.Load())
	}
	if notified.Load() < 2 { // starting, ready
		t.Fatalf("notify fired %d times, want >= 2", notified.Load())
	}
	if p.Active("i1") {
		t.Fatal("goroutine must end once ready")
	}
}

// A 502 from Caddy (upstream not there yet) is "not yet" until the budget
// is spent; then the instance is unhealthy. A later passing steady probe
// brings it back to ready at once.
func TestBegin_TimeoutThenRecover(t *testing.T) {
	var status atomic.Int32
	status.Store(502)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	srv.StartTLS()
	defer srv.Close()

	p, st := newTestProber(t, &stubInspector{running: true}, portOf(t, srv))
	p.timeoutOverride = 150 * time.Millisecond
	seedInstance(t, st, "i1")
	bindDomain(t, st, "app.example.com", "i1", "web", "root", "")
	target := Target{InstanceID: "i1", ServiceName: "web", ContainerName: "obacht-i1", TargetPort: 8080}

	p.Begin(target)
	waitState(t, st, "i1", StateStarting)
	waitState(t, st, "i1", StateUnhealthy)

	status.Store(200)
	p.RunSteady(context.Background(), []Target{target})
	waitState(t, st, "i1", StateReady)
}

// Steady state: ready flips to unhealthy only after three consecutive
// failures; one slow/bad answer does not flap.
func TestRunSteady_ThreeStrikes(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	srv.StartTLS()
	defer srv.Close()

	p, st := newTestProber(t, &stubInspector{running: true}, portOf(t, srv))
	seedInstance(t, st, "i1")
	bindDomain(t, st, "app.example.com", "i1", "web", "root", "")
	target := Target{InstanceID: "i1", ServiceName: "web", ContainerName: "obacht-i1", TargetPort: 8080}
	p.Begin(target)
	waitState(t, st, "i1", StateReady)

	ctx := context.Background()
	status.Store(500)
	p.RunSteady(ctx, []Target{target})
	p.RunSteady(ctx, []Target{target})
	if inst, _ := st.GetInstance(ctx, "i1"); inst.ServiceReady != StateReady {
		t.Fatalf("two failures must not flip: %q", inst.ServiceReady)
	}
	status.Store(200)
	p.RunSteady(ctx, []Target{target}) // resets the counter
	status.Store(500)
	p.RunSteady(ctx, []Target{target})
	p.RunSteady(ctx, []Target{target})
	if inst, _ := st.GetInstance(ctx, "i1"); inst.ServiceReady != StateReady {
		t.Fatalf("counter must reset after a pass: %q", inst.ServiceReady)
	}
	p.RunSteady(ctx, []Target{target})
	waitState(t, st, "i1", StateUnhealthy)
	status.Store(200)
	p.RunSteady(ctx, []Target{target})
	waitState(t, st, "i1", StateReady)
}

// Fallbacks without a domain: docker's own health when the image has a
// HEALTHCHECK, else running = ready. (The Linux direct-IP branch is covered
// by the HostPort path below, same HTTP code.)
func TestProbe_DockerHealthFallback(t *testing.T) {
	insp := &stubInspector{running: true}
	p, st := newTestProber(t, insp, 1) // no Caddy, no binding
	seedInstance(t, st, "i1")
	target := Target{InstanceID: "i1", ServiceName: "web", ContainerName: "obacht-i1"}
	ctx := context.Background()

	if ok, d := p.probe(ctx, target); !ok {
		t.Fatalf("running without health check must be ready: %s", d)
	}
	insp.health = "starting"
	if ok, _ := p.probe(ctx, target); ok {
		t.Fatal("health starting must not be ready")
	}
	insp.health = "unhealthy"
	if ok, _ := p.probe(ctx, target); ok {
		t.Fatal("health unhealthy must not be ready")
	}
	insp.health = "healthy"
	if ok, _ := p.probe(ctx, target); !ok {
		t.Fatal("health healthy must be ready")
	}
	insp.running = false
	if ok, _ := p.probe(ctx, target); ok {
		t.Fatal("stopped container must not be ready")
	}
	insp.missing = true
	if ok, _ := p.probe(ctx, target); ok {
		t.Fatal("missing container must not be ready")
	}
}

// A domain binding whose Caddy port is unreachable from the agent (Mac VM)
// must not pin the instance to "not yet": the probe falls through.
func TestProbe_CaddyUnreachableFallsThrough(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, ps, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	port, _ := strconv.Atoi(ps)
	insp := &stubInspector{running: true, health: "healthy"}
	p, st := newTestProber(t, insp, port)
	seedInstance(t, st, "i1")
	bindDomain(t, st, "app.example.com", "i1", "web", "root", "")
	ok, d := p.probe(context.Background(), Target{InstanceID: "i1", ServiceName: "web", ContainerName: "obacht-i1"})
	if !ok {
		t.Fatalf("expected fallthrough to docker health: %s", d)
	}
}

// System host_port services are probed on 127.0.0.1:<port> directly; the
// readiness path and expectStatus apply.
func TestProbe_HostPort(t *testing.T) {
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		w.WriteHeader(404)
	}))
	defer srv.Close()
	p, st := newTestProber(t, nil, 1)
	seedInstance(t, st, "s1")
	target := Target{InstanceID: "s1", ServiceName: "web", HostPort: true, TargetPort: portOf(t, srv), Config: &Config{Path: "/cam/"}}
	if ok, _ := p.probe(context.Background(), target); ok {
		t.Fatal("404 must not pass by default")
	}
	if gotPath.Load() != "/cam/" {
		t.Fatalf("path: %v", gotPath.Load())
	}
	target.Config.ExpectStatus = []int{404}
	if ok, d := p.probe(context.Background(), target); !ok {
		t.Fatalf("expectStatus 404 must pass: %s", d)
	}
}

// Redirects are answers, not followed.
func TestProbe_RedirectCountsAsAnswer(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()
	p, st := newTestProber(t, nil, 1)
	seedInstance(t, st, "s1")
	ok, _ := p.probe(context.Background(), Target{InstanceID: "s1", HostPort: true, TargetPort: portOf(t, srv)})
	if !ok || hits.Load() != 1 {
		t.Fatalf("302 must be accepted without following (ok=%v hits=%d)", ok, hits.Load())
	}
}

// Begin replaces a running goroutine (container recreated) and Forget stops
// it; a stale run must never write a state after it was replaced.
func TestBegin_ReplaceAndForget(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	srv.StartTLS()
	defer srv.Close()
	p, st := newTestProber(t, &stubInspector{running: true}, portOf(t, srv))
	p.timeoutOverride = 10 * time.Second
	seedInstance(t, st, "i1")
	bindDomain(t, st, "app.example.com", "i1", "web", "root", "")
	target := Target{InstanceID: "i1", ServiceName: "web", ContainerName: "obacht-i1"}
	p.Begin(target)
	p.Begin(target)
	if !p.Active("i1") {
		t.Fatal("expected an active run")
	}
	p.Forget("i1", "obacht-i1")
	if p.Active("i1") {
		t.Fatal("Forget must cancel the run")
	}
	time.Sleep(50 * time.Millisecond)
	if inst, _ := st.GetInstance(context.Background(), "i1"); inst.ServiceReady != StateStarting {
		t.Fatalf("cancelled run must not write a terminal state: %q", inst.ServiceReady)
	}
}
