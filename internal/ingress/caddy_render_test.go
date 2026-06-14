package ingress

import (
	"context"
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
