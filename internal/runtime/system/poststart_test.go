package system

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testRunner() (*hookRunner, *[]string, *sync.Mutex) {
	r := newHookRunner(slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.tcpWait = 2 * time.Second
	r.tcpInterval = 50 * time.Millisecond
	var (
		mu     sync.Mutex
		events []string
	)
	r.setSink(func(id, state, errMsg string) {
		mu.Lock()
		events = append(events, state+":"+errMsg)
		mu.Unlock()
	})
	return r, &events, &mu
}

func TestExpandHostData(t *testing.T) {
	hs := &HostServiceSpec{
		Args: []string{"serve", "--models", "${host.data}/models"},
		Env:  map[string]string{"OLLAMA_MODELS": "${host.data}/models", "PLAIN": "x"},
	}
	args, env := expandHostData(hs, "/Users/me/Library/obacht/host/data/dev.obacht.hostsvc.i1")
	if args[2] != "/Users/me/Library/obacht/host/data/dev.obacht.hostsvc.i1/models" {
		t.Fatalf("arg not expanded: %q", args[2])
	}
	if env["OLLAMA_MODELS"] != "/Users/me/Library/obacht/host/data/dev.obacht.hostsvc.i1/models" {
		t.Fatalf("env not expanded: %q", env["OLLAMA_MODELS"])
	}
	if env["PLAIN"] != "x" {
		t.Fatalf("unrelated env changed: %q", env["PLAIN"])
	}
	if env["OBACHT_DATA_DIR"] != "/Users/me/Library/obacht/host/data/dev.obacht.hostsvc.i1" {
		t.Fatalf("OBACHT_DATA_DIR missing: %v", env)
	}
	// The spec itself must stay untouched (it is re-rendered every tick).
	if hs.Env["OLLAMA_MODELS"] != "${host.data}/models" || hs.Args[2] != "${host.data}/models" {
		t.Fatalf("spec mutated: %+v", hs)
	}
	// The spec validator must accept the placeholder.
	full := validHostService()
	full.Env["OLLAMA_MODELS"] = "${host.data}/models"
	if err := (Spec{HostService: full}).Validate(); err != nil {
		t.Fatalf("${host.data} rejected by validate: %v", err)
	}
}

func TestPostStartHookValidation(t *testing.T) {
	good := []PostStartHTTP{
		{Method: "POST", URL: "http://127.0.0.1:11434/api/pull", Body: "{}"},
		{Method: "get", URL: "http://localhost/health"},
		{Method: "GET", URL: "http://localhost:8080/", TimeoutSeconds: 10},
	}
	for _, g := range good {
		if err := (PostStartHook{HTTP: &g}).validate(); err != nil {
			t.Errorf("valid hook rejected %+v: %v", g, err)
		}
	}
	bad := []PostStartHTTP{
		{Method: "PUT", URL: "http://127.0.0.1/x"},
		{Method: "GET", URL: "https://127.0.0.1/x"},
		{Method: "GET", URL: "http://127.0.0.2/x"},
		{Method: "GET", URL: "http://example.com/x"},
		{Method: "GET", URL: "http://127.0.0.1.evil.com/x"},
		{Method: "GET", URL: "http://localhost.evil/x"},
		{Method: "GET", URL: "http://127.0.0.1"},
		{Method: "GET", URL: "http://127.0.0.1:11434/x", TimeoutSeconds: 5},
		{Method: "GET", URL: "http://127.0.0.1:11434/x", TimeoutSeconds: 7201},
		{Method: "GET", URL: "http://127.0.0.1:11434/x\n"},
	}
	for _, b := range bad {
		if err := (PostStartHook{HTTP: &b}).validate(); err == nil {
			t.Errorf("hook accepted, want rejection: %+v", b)
		}
	}
	if err := (PostStartHook{}).validate(); err == nil {
		t.Error("hook without http block accepted")
	}
	// Through the host-service validator.
	hs := validHostService()
	hs.PostStart = []PostStartHook{{HTTP: &PostStartHTTP{Method: "POST", URL: "http://10.0.0.1/x"}}}
	if err := (Spec{HostService: hs}).Validate(); err == nil || !strings.Contains(err.Error(), "post_start[0]") {
		t.Fatalf("non-loopback url must be rejected via Spec.Validate, got %v", err)
	}
	m, ct, to := (PostStartHTTP{Method: "post", URL: "http://127.0.0.1/x"}).effective()
	if m != "POST" || ct != "application/json" || to != 1800*time.Second {
		t.Fatalf("defaults: %s %s %s", m, ct, to)
	}
}

func TestHookRunner_RunsInOrderAndReportsReady(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type")+" "+string(body))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r, events, emu := testRunner()
	r.start("i1", []PostStartHook{
		{HTTP: &PostStartHTTP{Method: "POST", URL: srv.URL + "/api/pull", Body: `{"model":"x"}`}},
		{HTTP: &PostStartHTTP{Method: "GET", URL: srv.URL + "/api/tags"}},
	})
	r.wait("i1")
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[0] != `POST /api/pull application/json {"model":"x"}` || calls[1] != "GET /api/tags  " {
		t.Fatalf("calls: %q", calls)
	}
	emu.Lock()
	defer emu.Unlock()
	if strings.Join(*events, ",") != "starting:,ready:" {
		t.Fatalf("events: %v", *events)
	}
	if r.shouldRun("i1", false) {
		t.Fatal("a finished successful run must not re-run on a no-op apply")
	}
	if !r.shouldRun("i1", true) {
		t.Fatal("a restart must re-run the hooks")
	}
	if !r.shouldRun("other", false) {
		t.Fatal("an instance never run in this process must run")
	}
}

func TestHookRunner_Non2xxIsUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	r, events, emu := testRunner()
	r.start("i1", []PostStartHook{{HTTP: &PostStartHTTP{Method: "GET", URL: srv.URL + "/x"}}})
	r.wait("i1")
	emu.Lock()
	defer emu.Unlock()
	if len(*events) != 2 || (*events)[0] != "starting:" || !strings.HasPrefix((*events)[1], "unhealthy:hook 0 GET ") || !strings.Contains((*events)[1], "HTTP 500") {
		t.Fatalf("events: %v", *events)
	}
	if r.shouldRun("i1", false) {
		t.Fatal("a failed run must wait for the cool-down before retrying on a no-op apply")
	}
}

func TestHookRunner_TCPWaitTimeoutIsUnhealthy(t *testing.T) {
	// Reserve a port and close it so nothing listens there.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	r, events, emu := testRunner()
	r.tcpWait = 300 * time.Millisecond
	r.start("i1", []PostStartHook{{HTTP: &PostStartHTTP{Method: "GET", URL: "http://" + addr + "/x"}}})
	r.wait("i1")
	emu.Lock()
	defer emu.Unlock()
	if len(*events) != 2 || !strings.HasPrefix((*events)[1], "unhealthy:service did not accept connections") {
		t.Fatalf("events: %v", *events)
	}
}

func TestHookRunner_RestartCancelsPreviousRun(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r, events, emu := testRunner()
	hooks := []PostStartHook{{HTTP: &PostStartHTTP{Method: "GET", URL: srv.URL + "/slow"}}}
	r.start("i1", hooks)
	time.Sleep(50 * time.Millisecond)
	if r.shouldRun("i1", true) {
		t.Fatal("must not start a second run while one is in flight")
	}
	r.start("i1", hooks) // explicit replace (re-apply after a restart)
	close(release)
	r.wait("i1")
	emu.Lock()
	defer emu.Unlock()
	// The cancelled first run must not report an outcome; the second does.
	for _, e := range *events {
		if strings.HasPrefix(e, "unhealthy") {
			t.Fatalf("cancelled run reported an outcome: %v", *events)
		}
	}
	if (*events)[len(*events)-1] != "ready:" {
		t.Fatalf("events: %v", *events)
	}
}

func TestHookAddr(t *testing.T) {
	if got := hookAddr("http://127.0.0.1:11434/api/pull"); got != "127.0.0.1:11434" {
		t.Fatalf("got %q", got)
	}
	if got := hookAddr("http://localhost/x"); got != "localhost:80" {
		t.Fatalf("got %q", got)
	}
}
