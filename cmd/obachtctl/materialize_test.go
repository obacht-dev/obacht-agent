package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestMaterializeWhoami(t *testing.T) {
	bytes, err := os.ReadFile("../../../obacht-registry/templates/whoami/manifest.yml")
	if err != nil {
		t.Skipf("registry sibling not present: %v", err)
	}
	out, err := materializeManifest(bytes, map[string]any{"name": "hello-pi"}, "inst-1", "whoami")
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	var spec matSpec
	if err := json.Unmarshal(out, &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if spec.Image != "traefik/whoami:latest" {
		t.Errorf("image: got %q", spec.Image)
	}
	if !strings.Contains(strings.Join(spec.Cmd, " "), "--name=hello-pi") {
		t.Errorf("cmd substitution failed: %v", spec.Cmd)
	}
	if spec.Network != "obacht-edge" {
		t.Errorf("network: %q", spec.Network)
	}
	if len(spec.Services) != 1 || spec.Services[0].TargetPort != 80 {
		t.Errorf("services: %+v", spec.Services)
	}
	if spec.Labels["obacht.template"] != "whoami" {
		t.Errorf("labels: %+v", spec.Labels)
	}
}

func TestMaterializeMissingCfgLeftLiteral(t *testing.T) {
	yml := `apiVersion: obacht.dev/v2
spec:
  runtime:
    type: container
    container:
      image: alpine
      cmd: ["echo", "${cfg.unknown}"]
`
	out, err := materializeManifest([]byte(yml), map[string]any{}, "i", "t")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "${cfg.unknown}") {
		t.Errorf("expected unknown placeholder kept literal, got %s", out)
	}
}

func TestMaterializeInstanceID(t *testing.T) {
	yml := `apiVersion: obacht.dev/v2
spec:
  runtime:
    type: container
    container:
      image: alpine
      env:
        INSTANCE: ${instance.id}
`
	out, err := materializeManifest([]byte(yml), nil, "abc-123", "t")
	if err != nil {
		t.Fatal(err)
	}
	var spec matSpec
	_ = json.Unmarshal(out, &spec)
	if spec.Env["INSTANCE"] != "abc-123" {
		t.Errorf("env: %+v", spec.Env)
	}
}
