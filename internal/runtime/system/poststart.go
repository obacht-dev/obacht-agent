package system

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ReadinessSink receives readiness transitions for host-service instances
// driven by post_start hooks: "starting" while hooks run, "ready" once all
// returned 2xx, "unhealthy" (with the error) when one failed. Wired by the
// reconciler, which persists the state and pushes it to the api.
type ReadinessSink func(instanceID, state, errMsg string)

// Hook runner timing. Tests shorten the waits via the struct fields.
const (
	// hookTCPWait bounds how long the runner waits for the service to
	// accept TCP connections on the first hook's host:port before giving up.
	hookTCPWait = 120 * time.Second
	// hookTCPInterval is the dial retry cadence during that wait.
	hookTCPInterval = time.Second
	// hookRetryAfter is the cool-down before a failed run is retried on a
	// later no-op apply (a changed plist or a reload retries at once).
	hookRetryAfter = 5 * time.Minute
)

// hookRunner runs post_start hooks, one goroutine per instance at a time. A
// new start for the same instance cancels the previous run.
type hookRunner struct {
	log  *slog.Logger
	sink ReadinessSink

	tcpWait     time.Duration
	tcpInterval time.Duration

	mu   sync.Mutex
	runs map[string]*hookRun
}

// hookRun is the record of the latest run for an instance.
type hookRun struct {
	cancel   context.CancelFunc
	done     chan struct{}
	running  bool
	failed   bool
	errMsg   string
	finished time.Time
}

func newHookRunner(log *slog.Logger) *hookRunner {
	if log == nil {
		log = slog.Default()
	}
	return &hookRunner{
		log:         log.With("component", "post_start"),
		tcpWait:     hookTCPWait,
		tcpInterval: hookTCPInterval,
		runs:        map[string]*hookRun{},
	}
}

func (r *hookRunner) setSink(s ReadinessSink) {
	r.mu.Lock()
	r.sink = s
	r.mu.Unlock()
}

func (r *hookRunner) emit(instanceID, state, errMsg string) {
	r.mu.Lock()
	s := r.sink
	r.mu.Unlock()
	if s != nil {
		s(instanceID, state, errMsg)
	}
}

// shouldRun decides whether Apply should (re)run the hooks: always after a
// service (re)start, once per agent process otherwise, and again after a
// cool-down when the last run failed. Never while a run is in flight.
func (r *hookRunner) shouldRun(instanceID string, restarted bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.runs[instanceID]
	if !ok {
		return true
	}
	if run.running {
		return false
	}
	if restarted {
		return true
	}
	return run.failed && time.Since(run.finished) > hookRetryAfter
}

// start cancels any in-flight run for the instance and starts a new one.
func (r *hookRunner) start(instanceID string, hooks []PostStartHook) {
	ctx, cancel := context.WithCancel(context.Background())
	run := &hookRun{cancel: cancel, done: make(chan struct{}), running: true}
	r.mu.Lock()
	if old, ok := r.runs[instanceID]; ok && old.running {
		old.cancel()
	}
	r.runs[instanceID] = run
	r.mu.Unlock()
	go r.run(ctx, instanceID, run, hooks)
}

// cancel stops a run (instance removed) and forgets it.
func (r *hookRunner) cancel(instanceID string) {
	r.mu.Lock()
	run, ok := r.runs[instanceID]
	if ok {
		run.cancel()
		delete(r.runs, instanceID)
	}
	r.mu.Unlock()
}

// wait blocks until the instance's current run finished (tests).
func (r *hookRunner) wait(instanceID string) {
	r.mu.Lock()
	run, ok := r.runs[instanceID]
	r.mu.Unlock()
	if ok {
		<-run.done
	}
}

func (r *hookRunner) finish(instanceID string, run *hookRun, errMsg string) {
	r.mu.Lock()
	run.running = false
	run.failed = errMsg != ""
	run.errMsg = errMsg
	run.finished = time.Now()
	r.mu.Unlock()
	close(run.done)
}

func (r *hookRunner) run(ctx context.Context, instanceID string, run *hookRun, hooks []PostStartHook) {
	r.emit(instanceID, "starting", "")
	if len(hooks) == 0 {
		r.finish(instanceID, run, "")
		r.emit(instanceID, "ready", "")
		return
	}
	// Wait for the service to listen before the first request: launchd
	// returned as soon as it spawned the process, Ollama takes a moment.
	addr := hookAddr(hooks[0].HTTP.URL)
	if err := r.waitTCP(ctx, addr); err != nil {
		if ctx.Err() != nil {
			r.finish(instanceID, run, "")
			return
		}
		msg := fmt.Sprintf("service did not accept connections on %s within %s", addr, r.tcpWait)
		r.log.Warn("post_start: service not reachable", "instance", instanceID, "addr", addr)
		r.finish(instanceID, run, msg)
		r.emit(instanceID, "unhealthy", msg)
		return
	}
	for i, h := range hooks {
		if err := r.runHook(ctx, instanceID, i, h.HTTP); err != nil {
			if ctx.Err() != nil {
				r.finish(instanceID, run, "")
				return
			}
			r.finish(instanceID, run, err.Error())
			r.emit(instanceID, "unhealthy", err.Error())
			return
		}
	}
	r.finish(instanceID, run, "")
	r.emit(instanceID, "ready", "")
}

// runHook sends one request. Logs carry the URL, never the body: it may
// hold config values.
func (r *hookRunner) runHook(ctx context.Context, instanceID string, idx int, p *PostStartHTTP) error {
	method, contentType, timeout := p.effective()
	r.log.Info("post_start hook start", "instance", instanceID, "hook", idx, "method", method, "url", p.URL, "timeout", timeout)
	started := time.Now()
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if p.Body != "" {
		body = strings.NewReader(p.Body)
	}
	req, err := http.NewRequestWithContext(hctx, method, p.URL, body)
	if err != nil {
		return fmt.Errorf("hook %d %s %s: %w", idx, method, p.URL, err)
	}
	if p.Body != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		r.log.Warn("post_start hook failed", "instance", instanceID, "hook", idx, "url", p.URL, "err", err, "took", time.Since(started))
		return fmt.Errorf("hook %d %s %s: %w", idx, method, p.URL, err)
	}
	// Drain so a streaming response (Ollama pull progress) completes.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		r.log.Warn("post_start hook non-2xx", "instance", instanceID, "hook", idx, "url", p.URL, "status", resp.StatusCode, "took", time.Since(started))
		return fmt.Errorf("hook %d %s %s: HTTP %d", idx, method, p.URL, resp.StatusCode)
	}
	r.log.Info("post_start hook done", "instance", instanceID, "hook", idx, "url", p.URL, "status", resp.StatusCode, "took", time.Since(started))
	return nil
}

// waitTCP retries a dial until it succeeds or the wait budget is spent.
func (r *hookRunner) waitTCP(ctx context.Context, addr string) error {
	deadline := time.Now().Add(r.tcpWait)
	for {
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.tcpInterval):
		}
	}
}

// hookAddr extracts host:port from a (validated, loopback) hook URL.
func hookAddr(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "127.0.0.1:80"
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(host, port)
}
