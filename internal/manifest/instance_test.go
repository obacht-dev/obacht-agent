package manifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const containerManifest = `apiVersion: obacht.dev/v2
kind: TemplateManifest
metadata:
  name: whoami
  version: "1.2.3"
spec:
  runtime:
    type: container
    container:
      image: traefik/whoami:latest
      cmd: ["--name=${cfg.name}"]
  services:
    - name: web
      targetPort: 80
  configSchema:
    - key: name
      type: text
      default: hello
`

func TestBuildInstanceConfigContainer(t *testing.T) {
	built, err := BuildInstanceConfig([]byte(containerManifest),
		map[string]any{"name": "blog"}, "inst-1", "whoami", "")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if built.Runtime != "container" {
		t.Errorf("runtime: %q", built.Runtime)
	}
	if built.Version != "1.2.3" {
		t.Errorf("version fallback to metadata failed: %q", built.Version)
	}
	m, ok := built.Config.(map[string]any)
	if !ok {
		t.Fatalf("config is not a map: %T", built.Config)
	}
	// __input must be preserved for the webapp's Configure prefill.
	input, ok := m["__input"].(map[string]any)
	if !ok || input["name"] != "blog" {
		t.Errorf("__input not preserved: %#v", m["__input"])
	}
	raw, _ := json.Marshal(built.Config)
	if !strings.Contains(string(raw), "--name=blog") {
		t.Errorf("cfg substitution missing: %s", raw)
	}
}

func TestBuildInstanceConfigExplicitVersionWins(t *testing.T) {
	built, err := BuildInstanceConfig([]byte(containerManifest), nil, "i", "whoami", "9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if built.Version != "9.9.9" {
		t.Errorf("explicit version should win: %q", built.Version)
	}
}

func TestBuildInstanceConfigUnsetValueError(t *testing.T) {
	// A container template with an unprovided ${cfg.X} and no default is a
	// genuine unset value → typed error.
	yml := `apiVersion: obacht.dev/v2
metadata:
  version: "1.0.0"
spec:
  runtime:
    type: container
    container:
      image: alpine
      env:
        TOKEN: ${cfg.api_token}
`
	_, err := BuildInstanceConfig([]byte(yml), map[string]any{}, "i", "t", "")
	var unset *UnsetValuesError
	if !errors.As(err, &unset) {
		t.Fatalf("expected UnsetValuesError, got %v", err)
	}
	if len(unset.Keys) != 1 || !strings.Contains(unset.Keys[0], "api_token") {
		t.Errorf("unexpected unset keys: %#v", unset.Keys)
	}
}

func TestRuntimeTypeProbe(t *testing.T) {
	if got := RuntimeType([]byte(containerManifest)); got != "container" {
		t.Errorf("RuntimeType: %q", got)
	}
	sys := `spec:
  runtime:
    type: system
`
	if got := RuntimeType([]byte(sys)); got != "system" {
		t.Errorf("RuntimeType system: %q", got)
	}
}
