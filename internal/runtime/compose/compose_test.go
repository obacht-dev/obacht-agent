package compose

import (
	"context"
	"strings"
	"testing"
)

type fakeSecrets struct{}

func (fakeSecrets) EnsureTemplateSecret(_ context.Context, _, key, charset string, length int) (string, error) {
	return "S-" + key + "-" + charset + "-" + strings.Repeat("x", max(0, length-len("S--")-len(key)-len(charset))), nil
}
func (fakeSecrets) DropTemplateSecrets(_ context.Context, _ string) error { return nil }

func TestPinImages(t *testing.T) {
	body := "services:\n  web:\n    image: ghost:5\n  db:\n    image: mysql:8.0\n"
	digests := map[string]string{
		"ghost:5":   "sha256:" + strings.Repeat("a", 64),
		"mysql:8.0": "sha256:" + strings.Repeat("b", 64),
	}
	out, err := pinImages(body, digests, false)
	if err != nil {
		t.Fatalf("pinImages: %v", err)
	}
	if !strings.Contains(out, "ghost:5@sha256:"+strings.Repeat("a", 64)) {
		t.Errorf("ghost not pinned: %s", out)
	}
	if !strings.Contains(out, "mysql:8.0@sha256:"+strings.Repeat("b", 64)) {
		t.Errorf("mysql not pinned: %s", out)
	}
}

func TestPinImagesAllowUnpinned(t *testing.T) {
	body := "services:\n  web:\n    image: ghost:5\n"
	out, err := pinImages(body, map[string]string{}, true)
	if err != nil {
		t.Fatalf("pinImages allowUnpinned: %v", err)
	}
	if !strings.Contains(out, "image: ghost:5") || strings.Contains(out, "@sha256") {
		t.Errorf("expected unpinned tag left as-is: %s", out)
	}
}

func TestPinImagesMissingDigest(t *testing.T) {
	body := "services:\n  web:\n    image: ghost:5\n"
	_, err := pinImages(body, map[string]string{}, false)
	if err == nil || !strings.Contains(err.Error(), "missing image digest") {
		t.Errorf("expected missing-digest error, got %v", err)
	}
}

func TestPinImagesAlreadyPinned(t *testing.T) {
	digestRef := "ghost:5@sha256:" + strings.Repeat("c", 64)
	body := "services:\n  web:\n    image: " + digestRef + "\n"
	out, err := pinImages(body, map[string]string{}, false)
	if err != nil {
		t.Fatalf("pinImages: %v", err)
	}
	if !strings.Contains(out, digestRef) {
		t.Errorf("already-pinned image was modified: %s", out)
	}
}

func TestRenderBodyCfgAndSecret(t *testing.T) {
	d := New("/tmp/test-compose-driver", fakeSecrets{}, DockerCLI{}, nil)
	spec := Spec{
		ComposeBody: "services:\n  web:\n    image: ghost:5\n    environment:\n      DB_PASS: ${secret.db_password}\n      SITE: ${cfg.site_title}\n",
		PrimaryService: "web", PrimaryPort: 2368,
		ImageDigests: map[string]string{"ghost:5": "sha256:" + strings.Repeat("a", 64)},
		SecretsSchema: []SecretField{{Key: "db_password", Length: 16, Charset: "alphanumeric"}},
		Config:        map[string]string{"site_title": "My Blog"},
	}
	out, err := d.renderBody(context.Background(), "demo-1", spec)
	if err != nil {
		t.Fatalf("renderBody: %v", err)
	}
	if strings.Contains(out, "${") {
		t.Errorf("placeholders remain: %s", out)
	}
	if !strings.Contains(out, "SITE: My Blog") {
		t.Errorf("cfg not substituted: %s", out)
	}
	if !strings.Contains(out, "DB_PASS: S-db_password-alphanumeric") {
		t.Errorf("secret not substituted: %s", out)
	}
	if !strings.Contains(out, "ghost:5@sha256:") {
		t.Errorf("image not pinned: %s", out)
	}
}

func TestParseSpecEmpty(t *testing.T) {
	if _, err := ParseSpec(""); err != ErrEmptySpec {
		t.Errorf("expected ErrEmptySpec, got %v", err)
	}
}

// TestRenderBodyCfgYAMLInjection proves a hostile config value placed inside a
// quoted official scalar cannot break out to inject new YAML keys / structure.
func TestRenderBodyCfgYAMLInjection(t *testing.T) {
	d := New("/tmp/test-compose-driver", fakeSecrets{}, DockerCLI{}, nil)
	// Official template style: cfg value lives inside a double-quoted scalar.
	const body = "services:\n" +
		"  web:\n" +
		"    image: ghost:5\n" +
		"    environment:\n" +
		"      SITE: \"${cfg.site}\"\n"
	// Attacker tries to close the scalar and inject privileged + a new key.
	malicious := "x\"\n    privileged: true\n    cap_add:\n      - SYS_ADMIN\ninjected: \"y"
	spec := Spec{
		ComposeBody:    body,
		PrimaryService: "web", PrimaryPort: 2368,
		ImageDigests: map[string]string{"ghost:5": "sha256:" + strings.Repeat("a", 64)},
		Config:       map[string]string{"site": malicious},
	}
	out, err := d.renderBody(context.Background(), "demo-1", spec)
	if err != nil {
		t.Fatalf("renderBody: %v", err)
	}
	if strings.Contains(out, "\n    privileged: true") {
		t.Fatalf("YAML injection succeeded — privileged leaked into structure:\n%s", out)
	}
	if strings.Contains(out, "\ninjected:") {
		t.Fatalf("YAML injection succeeded — new top-level key leaked:\n%s", out)
	}
	// The escaped value must still parse as valid YAML and stay one scalar.
	if !strings.Contains(out, `SITE: "x\"`) {
		t.Fatalf("expected escaped scalar, got:\n%s", out)
	}
}

// TestRenderBodyCustomNoEscape proves the custom-compose path (AllowUnpinnedImages)
// injects the user body verbatim (the whole document is the cfg value) and is
// guarded by the allowlist instead of escaping.
func TestRenderBodyCustomNoEscape(t *testing.T) {
	d := New("/tmp/test-compose-driver", fakeSecrets{}, DockerCLI{}, nil)
	userBody := "services:\n  app:\n    image: traefik/whoami:latest\n    restart: unless-stopped\n"
	spec := Spec{
		ComposeBody:         "${cfg.compose}",
		PrimaryService:      "app",
		PrimaryPort:         80,
		AllowUnpinnedImages: true,
		Config:              map[string]string{"compose": userBody},
	}
	out, err := d.renderBody(context.Background(), "demo-2", spec)
	if err != nil {
		t.Fatalf("renderBody custom: %v", err)
	}
	if !strings.Contains(out, "image: traefik/whoami:latest") {
		t.Fatalf("expected verbatim user body, got:\n%s", out)
	}
}

func max(a, b int) int { if a > b { return a }; return b }
