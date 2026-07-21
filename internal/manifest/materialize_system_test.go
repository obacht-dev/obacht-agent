package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

const ollamaManifest = `
apiVersion: obacht.dev/v2
kind: Template
metadata:
  name: ollama-host
  version: "1.0.0"
spec:
  runtime:
    type: system
    system:
      host_service:
        kind: ollama
        binary: ollama
        archive: tgz
        binary_url: https://github.com/ollama/ollama/releases/download/v0.1/ollama-darwin.tgz
        binary_digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        args: ["serve"]
        env:
          OLLAMA_HOST: "0.0.0.0:11434"
          OLLAMA_MODELS: "/var/lib/${instance.id}/models"
`

func TestMaterialize_SystemHostService(t *testing.T) {
	res, err := Materialize([]byte(ollamaManifest), nil, "inst-123", "ollama-host")
	if err != nil {
		t.Fatalf("materialize host-service: %v", err)
	}
	if res.Runtime != "system" {
		t.Fatalf("runtime = %q, want system", res.Runtime)
	}
	var parsed struct {
		HostService struct {
			Binary       string            `json:"binary"`
			BinaryURL    string            `json:"binary_url"`
			BinaryDigest string            `json:"binary_digest"`
			Archive      string            `json:"archive"`
			Args         []string          `json:"args"`
			Env          map[string]string `json:"env"`
		} `json:"host_service"`
	}
	if err := json.Unmarshal(res.Config, &parsed); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, res.Config)
	}
	hs := parsed.HostService
	if hs.Binary != "ollama" || len(hs.Args) != 1 || hs.Args[0] != "serve" {
		t.Fatalf("unexpected host_service: %+v", hs)
	}
	if hs.Archive != "tgz" {
		t.Fatalf("archive not carried through materialize: %q", hs.Archive)
	}
	// ${instance.id} must have been substituted in env.
	if got := hs.Env["OLLAMA_MODELS"]; got != "/var/lib/inst-123/models" {
		t.Fatalf("instance.id not substituted: %q", got)
	}
}

// A system manifest WITHOUT host_service must fail exactly like before — this
// guards that the Pi/legacy "unsupported runtime" behaviour is unchanged.
func TestMaterialize_SystemWithoutHostServiceRejected(t *testing.T) {
	m := `
apiVersion: obacht.dev/v2
kind: Template
metadata: { name: legacy-sys, version: "1.0.0" }
spec:
  runtime:
    type: system
    system:
      unit_name: foo.service
`
	_, err := Materialize([]byte(m), nil, "i", "legacy-sys")
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime.type") {
		t.Fatalf("expected unsupported-runtime error, got %v", err)
	}
}

const kioskManifest = `
apiVersion: obacht.dev/v2
kind: Template
metadata: { name: kiosk-mode, version: "1.0.0" }
spec:
  exclusivityGroup: display-output
  runtime:
    type: system
    system:
      kiosk: {}
      files:
        - path: /etc/obacht/kiosk/config.env
          content: "KIOSK_URL=${cfg.url}\n"
  configSchema:
    - { key: url, label: URL, type: text }
`

func TestMaterialize_Kiosk(t *testing.T) {
	res, err := Materialize([]byte(kioskManifest), map[string]any{"url": "https://ok.example"}, "i", "kiosk-mode")
	if err != nil {
		t.Fatalf("materialize kiosk: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Config, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["kiosk"]; !ok {
		t.Errorf("kiosk marker missing: %s", res.Config)
	}
	if got["exclusivity_group"] != "display-output" {
		t.Errorf("exclusivity group missing: %s", res.Config)
	}
	files, _ := got["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %s", res.Config)
	}
}

// A control character in a user config value must be rejected for a system
// template — it would inject a structural line into the rendered file.
func TestMaterialize_SystemRejectsControlCharInConfig(t *testing.T) {
	_, err := Materialize([]byte(kioskManifest),
		map[string]any{"url": "https://ok\nLD_PRELOAD=/tmp/evil.so"}, "i", "kiosk-mode")
	if err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("expected control-character rejection, got %v", err)
	}
}
