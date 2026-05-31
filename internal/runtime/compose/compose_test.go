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
	d := New("/tmp/test-compose-driver", fakeSecrets{}, nil)
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

func max(a, b int) int { if a > b { return a }; return b }
