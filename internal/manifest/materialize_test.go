package manifest

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
	out, err := Materialize(bytes, map[string]any{"name": "hello-pi"}, "inst-1", "whoami")
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	var spec matSpec
	if err := json.Unmarshal(out.Config, &spec); err != nil {
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
	out, err := Materialize([]byte(yml), map[string]any{}, "i", "t")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.Config), "${cfg.unknown}") {
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
	out, err := Materialize([]byte(yml), nil, "abc-123", "t")
	if err != nil {
		t.Fatal(err)
	}
	var spec matSpec
	_ = json.Unmarshal(out.Config, &spec)
	if spec.Env["INSTANCE"] != "abc-123" {
		t.Errorf("env: %+v", spec.Env)
	}
}

func TestMaterializeComposeBundle(t *testing.T) {
	manifest := []byte(`apiVersion: obacht.dev/v2
kind: TemplateManifest
metadata:
  name: ghost-bundle
  version: "1.0.0"
spec:
  minSpecVersion: v2.1
  runtime:
    type: compose
    compose:
      primaryService: ghost
      primaryPort: 2368
      imageDigests:
        ghost:5: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        mysql:8.0: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      body: |
        services:
          ghost:
            image: ghost:5
            environment:
              SITE: ${cfg.site_title}
              DB_PASS: ${secret.db_password}
          db:
            image: mysql:8.0
  secretsSchema:
    - key: db_password
      length: 32
      charset: alphanumeric
  services:
    - name: web
      targetService: ghost
      targetPort: 2368
  configSchema:
    - key: site_title
      type: text
      label: Site title
      default: My Blog
`)
	out, err := Materialize(manifest, map[string]any{"site_title": "Hello"}, "ghost-1", "ghost-bundle")
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	if out.Runtime != "compose" {
		t.Fatalf("runtime: got %q want compose", out.Runtime)
	}
	var spec matComposeSpec
	if err := json.Unmarshal(out.Config, &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if spec.PrimaryService != "ghost" || spec.PrimaryPort != 2368 {
		t.Errorf("primary: %s:%d", spec.PrimaryService, spec.PrimaryPort)
	}
	if spec.Config["site_title"] != "Hello" {
		t.Errorf("config not flattened: %#v", spec.Config)
	}
	if len(spec.SecretsSchema) != 1 || spec.SecretsSchema[0].Key != "db_password" || spec.SecretsSchema[0].Length != 32 {
		t.Errorf("secrets: %#v", spec.SecretsSchema)
	}
	if len(spec.Services) != 1 || spec.Services[0].TargetService != "ghost" || spec.Services[0].TargetPort != 2368 {
		t.Errorf("services: %#v", spec.Services)
	}
	if !strings.Contains(spec.ComposeBody, "${cfg.site_title}") {
		t.Errorf("cfg should be left for agent; body=%s", spec.ComposeBody)
	}
	if !strings.Contains(spec.ComposeBody, "${secret.db_password}") {
		t.Errorf("secret should be left for agent; body=%s", spec.ComposeBody)
	}
	if spec.ImageDigests["ghost:5"] == "" {
		t.Errorf("digests missing: %#v", spec.ImageDigests)
	}
}
