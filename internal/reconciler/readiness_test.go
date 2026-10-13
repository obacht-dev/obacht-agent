package reconciler

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/readiness"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

func testReconciler(t *testing.T) (*Reconciler, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(st, nil, log, time.Second)
	r.SetReadiness(readiness.New(st, nil, 443, log))
	return r, st
}

// readinessTarget picks the service a visitor reaches: the bound one when
// the template exposes several, else the first routable; it maps each
// runtime to the right container/host target and steps aside for
// host-service post_start hooks.
func TestReadinessTarget(t *testing.T) {
	r, _ := testReconciler(t)

	cont := store.Instance{ID: "c1", Runtime: store.RuntimeContainer, ConfigJSON: `{"image":"x","services":[
		{"name":"api","targetPort":9000},
		{"name":"web","targetPort":8080,"readiness":{"path":"/health","timeoutSeconds":900}}]}`}
	tg, ok := r.readinessTarget(cont, map[string]string{"c1": "web"})
	if !ok || tg.ServiceName != "web" || tg.ContainerName != "obacht-c1" || tg.TargetPort != 8080 || tg.Config == nil || tg.Config.Path != "/health" {
		t.Fatalf("container target: %+v %v", tg, ok)
	}
	tg, _ = r.readinessTarget(cont, nil)
	if tg.ServiceName != "api" {
		t.Fatalf("without a binding the first routable service wins: %+v", tg)
	}

	comp := store.Instance{ID: "b1", Runtime: store.RuntimeCompose, ConfigJSON: `{"compose_body":"services: {}","primary_service":"ghost","primary_port":2368,
		"services":[{"name":"web","targetService":"ghost","targetPort":2368,"readiness":{"path":"/ghost/"}}]}`}
	tg, ok = r.readinessTarget(comp, nil)
	if !ok || tg.ContainerName != "obacht-b1-ghost-1" || tg.TargetPort != 2368 || tg.Config.Path != "/ghost/" {
		t.Fatalf("compose target: %+v %v", tg, ok)
	}

	sys := store.Instance{ID: "s1", Runtime: store.RuntimeSystem, ConfigJSON: `{"managed_service":{"binary":"mediamtx","binary_url":"https://github.com/x/y","binary_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"services":[{"name":"web","target_type":"host_port","target_port":8888,"readiness":{"path":"/cam/"}}]}`}
	tg, ok = r.readinessTarget(sys, nil)
	if !ok || !tg.HostPort || tg.TargetPort != 8888 || tg.ContainerName != "" || tg.Config.Path != "/cam/" {
		t.Fatalf("system target: %+v %v", tg, ok)
	}

	hooked := store.Instance{ID: "h1", Runtime: store.RuntimeSystem, ConfigJSON: `{"host_service":{"kind":"ollama","binary":"ollama","binary_url":"https://ollama.com/x","binary_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"post_start":[{"http":{"method":"POST","url":"http://127.0.0.1:11434/api/pull"}}]},
		"services":[{"name":"api","target_type":"host_port","target_port":11434}]}`}
	if _, ok := r.readinessTarget(hooked, nil); ok {
		t.Fatal("a host service with post_start hooks must not be probed")
	}

	none := store.Instance{ID: "n1", Runtime: store.RuntimeContainer, ConfigJSON: `{"image":"x"}`}
	if _, ok := r.readinessTarget(none, nil); ok {
		t.Fatal("no services, nothing to probe")
	}
}

// The post_start hook sink persists the state and audits a failure.
func TestHookReadinessSink(t *testing.T) {
	r, st := testReconciler(t)
	ctx := context.Background()
	if err := st.UpsertInstance(ctx, store.Instance{ID: "h1", TemplateID: "ollama-host", Runtime: store.RuntimeSystem, DesiredState: store.DesiredInstalled}); err != nil {
		t.Fatal(err)
	}
	var pushes int
	r.SetChangeNotifier(func() { pushes++ })

	r.hookReadiness("h1", readiness.StateStarting, "")
	r.hookReadiness("h1", readiness.StateStarting, "") // no transition, no push
	r.hookReadiness("h1", readiness.StateReady, "")
	inst, _ := st.GetInstance(ctx, "h1")
	if inst.ServiceReady != readiness.StateReady || inst.ReadyAt.IsZero() {
		t.Fatalf("ready not recorded: %+v", inst)
	}
	if pushes != 2 {
		t.Fatalf("expected one push per transition, got %d", pushes)
	}
	r.hookReadiness("h1", readiness.StateUnhealthy, "hook 0 POST http://127.0.0.1:11434/api/pull: HTTP 500")
	inst, _ = st.GetInstance(ctx, "h1")
	if inst.ServiceReady != readiness.StateUnhealthy || !inst.ReadyAt.IsZero() {
		t.Fatalf("unhealthy must clear ready_at: %+v", inst)
	}
}

// Stopping an instance clears its readiness signal.
func TestResetReadinessOnStop(t *testing.T) {
	r, st := testReconciler(t)
	ctx := context.Background()
	if err := st.UpsertInstance(ctx, store.Instance{ID: "c1", TemplateID: "whoami", Runtime: store.RuntimeContainer, DesiredState: store.DesiredStopped}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetServiceReady(ctx, "c1", readiness.StateReady, time.Now()); err != nil {
		t.Fatal(err)
	}
	inst, _ := st.GetInstance(ctx, "c1")
	r.resetReadiness(ctx, *inst)
	inst, _ = st.GetInstance(ctx, "c1")
	if inst.ServiceReady != "" || !inst.ReadyAt.IsZero() {
		t.Fatalf("stop must reset readiness: %+v", inst)
	}
}
