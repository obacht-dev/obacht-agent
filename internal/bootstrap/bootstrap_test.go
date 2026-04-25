package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"log/slog"

	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

func TestRun_HappyPath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var seenBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/validate-install") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Server.URL = srv.URL
	cfg.Server.DeviceID = "dev-xyz"
	cfg.Server.AuthToken = "tok-abc"

	if err := Run(ctx, slog.Default(), st, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seenBody["token"] != "tok-abc" {
		t.Fatalf("token not posted, got %v", seenBody)
	}

	// Idempotency: second call must be a no-op (no new HTTP request needed).
	srv.Close()
	if err := Run(ctx, slog.Default(), st, cfg); err != nil {
		t.Fatalf("Run idempotent: %v", err)
	}
}

func TestRun_Skipped(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := Run(ctx, slog.Default(), st, &config.Config{}); err == nil || err != ErrSkipped {
		t.Fatalf("expected ErrSkipped, got %v", err)
	}
}

func TestRun_RejectedToken(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "expired"})
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Server.URL = srv.URL
	cfg.Server.DeviceID = "dev-xyz"
	cfg.Server.AuthToken = "tok-abc"
	if err := Run(ctx, slog.Default(), st, cfg); err == nil {
		t.Fatal("expected error for rejected token")
	}
}
