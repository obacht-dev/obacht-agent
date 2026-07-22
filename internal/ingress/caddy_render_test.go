package ingress

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/obacht-dev/obacht-agent/internal/config"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

func renderWith(t *testing.T, cfg config.IngressConfig) string {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	m := &Manager{store: st, cfg: cfg}
	body, _, err := m.renderCaddyfile(context.Background())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return body
}

// Pi defaults: no global port overrides, empty-config fallback on :80.
func TestRenderPiPortsDefault(t *testing.T) {
	out := renderWith(t, config.IngressConfig{HTTPPort: 80, HTTPSPort: 443})
	if strings.Contains(out, "http_port") || strings.Contains(out, "https_port") {
		t.Errorf("default ports must not emit global overrides:\n%s", out)
	}
	if !strings.Contains(out, ":80 {") {
		t.Errorf("expected :80 fallback listener:\n%s", out)
	}
}

// Basic auth: a domain with credentials gets a basic_auth block guarding the
// whole site; corrupt credentials fail closed with a 503 instead of serving
// the app unprotected.
func TestRenderBasicAuth(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.UpsertDomain(ctx, "auth.example.com", store.DomainStatusReady); err != nil {
		t.Fatal(err)
	}
	hash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	if err := st.SetDomainBasicAuth(ctx, "auth.example.com", "admin", hash); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDomain(ctx, "open.example.com", store.DomainStatusReady); err != nil {
		t.Fatal(err)
	}

	m := &Manager{store: st, cfg: config.IngressConfig{HTTPPort: 80, HTTPSPort: 443}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body, _, err := m.renderCaddyfile(ctx)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(body, "basic_auth {\n\t\tadmin "+hash+"\n\t}") {
		t.Errorf("missing basic_auth block:\n%s", body)
	}
	// The unprotected domain must not inherit the directive.
	openBlock := body[strings.Index(body, "open.example.com {"):]
	if strings.Contains(openBlock, "basic_auth") {
		t.Errorf("open.example.com must not carry basic_auth:\n%s", body)
	}

	// Corrupt the hash directly in the DB (bypasses SetDomainBasicAuth
	// validation) — render must fail closed with a 503.
	if _, err := st.DB().Exec(`UPDATE domains SET basic_auth_hash = 'not-a-hash' WHERE domain = 'auth.example.com'`); err != nil {
		t.Fatal(err)
	}
	body, _, err = m.renderCaddyfile(ctx)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(body, "basic_auth") {
		t.Errorf("corrupt hash must not render basic_auth:\n%s", body)
	}
	authBlock := body[strings.Index(body, "auth.example.com {"):]
	if !strings.Contains(authBlock[:strings.Index(authBlock, "}")], "503") {
		t.Errorf("corrupt basic auth must serve 503:\n%s", body)
	}
}

// Mac ports: global http_port/https_port (so ACME uses the forwarded port)
// and the empty-config fallback listens on the http port.
func TestRenderMacPortsGlobal(t *testing.T) {
	out := renderWith(t, config.IngressConfig{HTTPPort: 8080, HTTPSPort: 8443})
	if !strings.Contains(out, "http_port 8080") {
		t.Errorf("missing http_port 8080:\n%s", out)
	}
	if !strings.Contains(out, "https_port 8443") {
		t.Errorf("missing https_port 8443:\n%s", out)
	}
	if !strings.Contains(out, ":8080 {") {
		t.Errorf("expected :8080 fallback listener:\n%s", out)
	}
}
