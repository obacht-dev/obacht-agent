package manifest

import (
	"encoding/json"
	"reflect"
	"testing"
)

const secretsManifest = `
apiVersion: obacht.dev/v2
metadata:
  name: demo
  version: 1.0.0
spec:
  configSchema:
    - key: siteName
      label: Site name
      type: text
    - key: adminPassword
      label: Admin password
      type: secret
    - key: smtpPassword
      label: SMTP password
      type: secret
  runtime:
    type: container
    container:
      image: nginx:latest
`

func TestSecretConfigKeys(t *testing.T) {
	got := SecretConfigKeys([]byte(secretsManifest))
	want := []string{"adminPassword", "smtpPassword"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SecretConfigKeys = %v, want %v", got, want)
	}
	if got := SecretConfigKeys([]byte("not: [valid")); len(got) != 0 {
		t.Fatalf("invalid manifest should yield empty list, got %v", got)
	}
}

func TestBuildInstanceConfigWritesSecretKeysMarker(t *testing.T) {
	built, err := BuildInstanceConfig([]byte(secretsManifest), map[string]any{
		"siteName":      "hello",
		"adminPassword": "hunter2",
	}, "inst-1", "demo", "")
	if err != nil {
		t.Fatalf("BuildInstanceConfig: %v", err)
	}
	m, ok := built.Config.(map[string]any)
	if !ok {
		t.Fatalf("config is not a map: %T", built.Config)
	}
	keys, ok := m[SecretKeysMarker].([]string)
	if !ok || !reflect.DeepEqual(keys, []string{"adminPassword", "smtpPassword"}) {
		t.Fatalf("marker = %v (%T)", m[SecretKeysMarker], m[SecretKeysMarker])
	}
}

func TestRedactedInputEchoWithMarker(t *testing.T) {
	cfg := map[string]any{
		"image": "nginx:latest",
		"__input": map[string]any{
			"siteName":      "hello",
			"adminPassword": "hunter2",
			"smtpPassword":  "",
		},
		SecretKeysMarker: []string{"adminPassword", "smtpPassword"},
	}
	raw, _ := json.Marshal(cfg)
	got := RedactedInputEcho(string(raw))
	want := map[string]any{
		"siteName":      "hello",
		"adminPassword": SecretKeepSentinel,
		"smtpPassword":  "", // empty stays empty — sentinel only stands in for real values
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("echo = %v, want %v", got, want)
	}
}

func TestRedactedInputEchoLegacyHeuristic(t *testing.T) {
	// No marker → legacy row → redact.IsSecretKey heuristic.
	cfg := map[string]any{
		"__input": map[string]any{
			"siteName":      "hello",
			"adminPassword": "hunter2",
		},
	}
	raw, _ := json.Marshal(cfg)
	got := RedactedInputEcho(string(raw))
	if got["adminPassword"] != SecretKeepSentinel {
		t.Fatalf("legacy adminPassword not redacted: %v", got)
	}
	if got["siteName"] != "hello" {
		t.Fatalf("legacy non-secret mangled: %v", got)
	}
}

func TestRedactedInputEchoEmptyMarkerIsAuthoritative(t *testing.T) {
	// Marker present but empty → nothing is secret, heuristic must NOT run.
	cfg := map[string]any{
		"__input": map[string]any{
			"adminPassword": "not-actually-secret-typed",
		},
		SecretKeysMarker: []string{},
	}
	raw, _ := json.Marshal(cfg)
	got := RedactedInputEcho(string(raw))
	if got["adminPassword"] != "not-actually-secret-typed" {
		t.Fatalf("empty marker should disable heuristic, got %v", got)
	}
}

func TestRedactedInputEchoNoInput(t *testing.T) {
	if got := RedactedInputEcho(`{"image":"nginx"}`); got != nil {
		t.Fatalf("expected nil for config without __input, got %v", got)
	}
	if got := RedactedInputEcho(""); got != nil {
		t.Fatalf("expected nil for empty config, got %v", got)
	}
}

func TestResolveSecretSentinels(t *testing.T) {
	stored := map[string]any{
		"__input": map[string]any{
			"adminPassword": "hunter2",
			"siteName":      "hello",
		},
	}
	rawStored, _ := json.Marshal(stored)

	in := map[string]any{
		"adminPassword": SecretKeepSentinel,
		"siteName":      "renamed",
		"newSecret":     SecretKeepSentinel, // no stored counterpart
	}
	got := ResolveSecretSentinels(in, string(rawStored))
	want := map[string]any{
		"adminPassword": "hunter2",
		"siteName":      "renamed",
		"newSecret":     "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved = %v, want %v", got, want)
	}

	// No sentinels → identity (same map back, no copy).
	same := map[string]any{"a": "b"}
	if out := ResolveSecretSentinels(same, string(rawStored)); !reflect.DeepEqual(out, same) {
		t.Fatalf("identity case broken: %v", out)
	}

	// Stored sentinel must never survive as a value.
	storedBad, _ := json.Marshal(map[string]any{
		"__input": map[string]any{"adminPassword": SecretKeepSentinel},
	})
	out := ResolveSecretSentinels(map[string]any{"adminPassword": SecretKeepSentinel}, string(storedBad))
	if out["adminPassword"] != "" {
		t.Fatalf("stored sentinel leaked through: %v", out)
	}
}
