package sync

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/obacht-dev/obacht-agent/internal/api"
	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// triggerSpy simulates a reconciler trigger so we can assert it's NEVER
// called when an inbound desired-state event is denied.
type triggerSpy struct{ count int }

func (t *triggerSpy) Trigger() { t.count++ }

// TestDenyInboundDesiredStateEvents verifies the S2 hardening:
// every "agent:upsert_*" / "agent:delete_*" handler must drop the event
// and write a security.deny entry into the audit log without touching the
// SQLite store.
func TestDenyInboundDesiredStateEvents(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agent.db")
	logPath := filepath.Join(dir, "audit.log")

	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	w, err := audit.New(st, logPath)
	if err != nil {
		t.Fatalf("audit new: %v", err)
	}
	defer w.Close()

	client := api.New("", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	spy := &triggerSpy{}
	s := New(client, st, spy, "test-device", "test", slog.New(slog.NewTextHandler(io.Discard, nil)), w)

	// Wire handlers (Run() does this; here we exercise Run's setup path
	// directly by calling it briefly with an immediately-cancelled ctx).
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	s.Run(cctx) // returns once ctx is done; handlers are registered first.

	denied := []string{
		"agent:upsert_instance",
		"agent:delete_instance",
		"agent:upsert_binding",
		"agent:delete_binding",
		"agent:upsert_domain",
		"agent:delete_domain",
	}
	for _, ev := range denied {
		h := getHandler(t, client, ev)
		// Provide a realistic-looking payload so the handler hits the same
		// JSON unmarshal path it would in production.
		payload, _ := json.Marshal(map[string]any{"id": "x", "domain": "x.example.com"})
		h([]json.RawMessage{payload})
	}

	if spy.count != 0 {
		t.Fatalf("Trigger() must NOT be called for denied events, got %d calls", spy.count)
	}

	rows, err := w.Tail(ctx, 100)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}

	denies := 0
	for _, r := range rows {
		if r.Op == "security.deny" && r.Result == audit.ResultDenied {
			denies++
		}
	}
	if denies != len(denied) {
		t.Fatalf("expected %d security.deny entries, got %d (rows=%d)", len(denied), denies, len(rows))
	}

	// Store must be untouched.
	insts, _ := st.ListInstances(ctx)
	if len(insts) != 0 {
		t.Fatalf("denied events leaked into store: %d instances", len(insts))
	}
	doms, _ := st.ListDomains(ctx)
	if len(doms) != 0 {
		t.Fatalf("denied events leaked into store: %d domains", len(doms))
	}
}

// getHandler reaches into api.Client to fetch the registered handler for an
// event. We only read the map under its own lock, so this is race-safe.
func getHandler(t *testing.T, c *api.Client, event string) func([]json.RawMessage) {
	t.Helper()
	h := c.Handler(event)
	if h == nil {
		t.Fatalf("no handler registered for %s", event)
	}
	return h
}
