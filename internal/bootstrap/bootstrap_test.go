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
		if !strings.HasSuffix(r.URL.Path, "/auth/rpi-device") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_token": "jwt-xyz",
			"device_id":    seenBody["device_id"],
		})
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Server.URL = srv.URL
	cfg.Server.DeviceID = "dev-xyz"
	cfg.Server.AuthToken = "tok-abc"

	tok, err := Run(ctx, slog.Default(), st, cfg, "test")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if tok.JWT != "jwt-xyz" {
		t.Fatalf("expected jwt, got %q", tok.JWT)
	}
	if seenBody["install_token"] != "tok-abc" {
		t.Fatalf("install_token not posted, got %v", seenBody)
	}

	// Idempotency: second call must be a no-op (no new HTTP request needed).
	srv.Close()
	tok2, err := Run(ctx, slog.Default(), st, cfg, "test")
	if err != nil {
		t.Fatalf("Run idempotent: %v", err)
	}
	if tok2.JWT != "jwt-xyz" {
		t.Fatalf("idempotent run lost jwt: %q", tok2.JWT)
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
	if _, err := Run(ctx, slog.Default(), st, &config.Config{}, "test"); err != ErrSkipped {
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
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "expired"})
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Server.URL = srv.URL
	cfg.Server.DeviceID = "dev-xyz"
	cfg.Server.AuthToken = "tok-abc"
	if _, err := Run(ctx, slog.Default(), st, cfg, "test"); err == nil {
		t.Fatal("expected error for rejected token")
	}
}
