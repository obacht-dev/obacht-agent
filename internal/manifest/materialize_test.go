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

// minDiskManifest builds a compose manifest with a template-wide disk floor
// (or none) and a select field with optional optionRequirements (v2.9), so the
// materializer's requiredDiskMb resolution can be exercised end to end.
func minDiskManifest(resources, optionRequirements string) []byte {
	return []byte(`apiVersion: obacht.dev/v2
kind: TemplateManifest
metadata:
  name: llm-bundle
  version: "1.0.0"
spec:
  minSpecVersion: v2.9
  compatibility:
    architectures: [arm64]
` + resources + `
  runtime:
    type: compose
    compose:
      primaryService: llm
      primaryPort: 8080
      imageDigests:
        llm:1: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      body: |
        services:
          llm:
            image: llm:1
  configSchema:
    - key: model_pack
      type: select
      label: Model pack
      default: none
      options:
        - { value: none, label: None }
        - { value: eu, label: EU pack }
        - { value: small, label: Small pack }
` + optionRequirements + `
`)
}

const minDiskResources = `    resources:
      minRamMb: 4096
      minDiskMb: 2048`

const minDiskOptionReqs = `      optionRequirements:
        eu:
          minDiskMb: 40960
        small:
          minRamMb: 8192`

func materializeMinDisk(t *testing.T, manifest []byte, cfg map[string]any) matComposeSpec {
	t.Helper()
	out, err := Materialize(manifest, cfg, "llm-1", "llm-bundle")
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	var spec matComposeSpec
	if err := json.Unmarshal(out.Config, &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return spec
}

func TestMaterializeMinDiskMb(t *testing.T) {
	// (a) user picks an option with its own requirement → that value wins.
	spec := materializeMinDisk(t, minDiskManifest(minDiskResources, minDiskOptionReqs), map[string]any{"model_pack": "eu"})
	if spec.MinDiskMb != 40960 {
		t.Errorf("eu: MinDiskMb = %d, want 40960", spec.MinDiskMb)
	}
	// Option entry without minDiskMb (only RAM) → floor.
	spec = materializeMinDisk(t, minDiskManifest(minDiskResources, minDiskOptionReqs), map[string]any{"model_pack": "small"})
	if spec.MinDiskMb != 2048 {
		t.Errorf("small: MinDiskMb = %d, want 2048 (floor)", spec.MinDiskMb)
	}

	// (b) user picks an option with no entry → template floor. Also covers
	// the default path: no user value, configSchema default "none" applies.
	spec = materializeMinDisk(t, minDiskManifest(minDiskResources, minDiskOptionReqs), map[string]any{"model_pack": "none"})
	if spec.MinDiskMb != 2048 {
		t.Errorf("none: MinDiskMb = %d, want 2048 (floor)", spec.MinDiskMb)
	}
	spec = materializeMinDisk(t, minDiskManifest(minDiskResources, minDiskOptionReqs), nil)
	if spec.MinDiskMb != 2048 {
		t.Errorf("default: MinDiskMb = %d, want 2048 (floor)", spec.MinDiskMb)
	}

	// (c) no optionRequirements at all → floor regardless of choice.
	spec = materializeMinDisk(t, minDiskManifest(minDiskResources, ""), map[string]any{"model_pack": "eu"})
	if spec.MinDiskMb != 2048 {
		t.Errorf("no optionRequirements: MinDiskMb = %d, want 2048", spec.MinDiskMb)
	}

	// (d) no resources block → 0 (agent floor only); the field is omitted
	// from the JSON so older agents' specs stay byte-identical.
	out, err := Materialize(minDiskManifest("", ""), map[string]any{"model_pack": "eu"}, "llm-1", "llm-bundle")
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	if strings.Contains(string(out.Config), "min_disk_mb") {
		t.Errorf("no resources: min_disk_mb should be omitted, got %s", out.Config)
	}

	// Malformed values fail open: an unknown option and a non-numeric
	// requirement both degrade to the floor, never an error.
	spec = materializeMinDisk(t, minDiskManifest(minDiskResources, minDiskOptionReqs), map[string]any{"model_pack": "bogus"})
	if spec.MinDiskMb != 2048 {
		t.Errorf("unknown option: MinDiskMb = %d, want 2048", spec.MinDiskMb)
	}
	spec = materializeMinDisk(t, minDiskManifest(minDiskResources, "      optionRequirements:\n        eu: notamap"), map[string]any{"model_pack": "eu"})
	if spec.MinDiskMb != 2048 {
		t.Errorf("malformed entry: MinDiskMb = %d, want 2048", spec.MinDiskMb)
	}
}

func TestMaterializeMinDiskMbContainer(t *testing.T) {
	// The container path resolves the same figure into container.Spec.
	manifest := []byte(`apiVersion: obacht.dev/v2
kind: TemplateManifest
metadata:
  name: llm-single
  version: "1.0.0"
spec:
  minSpecVersion: v2.9
  compatibility:
    architectures: [arm64]
    resources:
      minDiskMb: 1024
  runtime:
    type: container
    container:
      image: llm:1
  configSchema:
    - key: model_pack
      type: select
      label: Model pack
      default: none
      options:
        - { value: none, label: None }
        - { value: eu, label: EU pack }
      optionRequirements:
        eu:
          minDiskMb: 40960
`)
	out, err := Materialize(manifest, map[string]any{"model_pack": "eu"}, "llm-1", "llm-single")
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	var spec matSpec
	if err := json.Unmarshal(out.Config, &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if spec.MinDiskMb != 40960 {
		t.Errorf("container eu: MinDiskMb = %d, want 40960", spec.MinDiskMb)
	}
}
