package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

// Spec v2.9 fields must survive materialisation: the agent stores what
// BuildInstanceConfig emits, so a typed copy that drops readiness or
// post_start silently disables the feature for every install.

const ollamaV2Manifest = `
apiVersion: obacht.dev/v2
kind: Template
metadata:
  name: ollama-host
  version: "2.0.0"
spec:
  minSpecVersion: "v2.9"
  runtime:
    type: system
    system:
      host_service:
        kind: ollama
        binary: ollama
        archive: tgz
        binary_url: https://github.com/ollama/ollama/releases/download/v0.40.0/ollama-darwin.tgz
        binary_digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        args: ["serve"]
        env:
          OLLAMA_HOST: "0.0.0.0:11434"
          OLLAMA_MODELS: "${host.data}/models"
        post_start:
          - http:
              method: POST
              url: http://127.0.0.1:11434/api/pull
              body: '{"model":"${cfg.model}","stream":false}'
              timeoutSeconds: 3600
  configSchema:
    - key: model
      label: Model
      type: select
      default: "gemma3:4b"
      options:
        - { value: "gemma3:4b", label: "Gemma 3 4B" }
        - { value: "llama3.2:3b", label: "Llama 3.2 3B" }
`

type hostServiceOut struct {
	HostService struct {
		Env       map[string]string `json:"env"`
		PostStart []struct {
			HTTP struct {
				Method         string `json:"method"`
				URL            string `json:"url"`
				Body           string `json:"body"`
				ContentType    string `json:"contentType"`
				TimeoutSeconds int    `json:"timeoutSeconds"`
			} `json:"http"`
		} `json:"post_start"`
	} `json:"host_service"`
}

func TestBuildInstanceConfig_HostServicePostStartAndHostData(t *testing.T) {
	built, err := BuildInstanceConfig([]byte(ollamaV2Manifest), map[string]any{"model": "llama3.2:3b"}, "inst-1", "ollama-host", "")
	if err != nil {
		t.Fatalf("BuildInstanceConfig: %v", err)
	}
	raw, _ := json.Marshal(built.Config)
	var out hostServiceOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	hs := out.HostService
	if len(hs.PostStart) != 1 {
		t.Fatalf("post_start dropped by materialise: %s", raw)
	}
	h := hs.PostStart[0].HTTP
	if h.Method != "POST" || h.URL != "http://127.0.0.1:11434/api/pull" || h.TimeoutSeconds != 3600 {
		t.Fatalf("post_start http not carried through: %+v", h)
	}
	if want := `{"model":"llama3.2:3b","stream":false}`; h.Body != want {
		t.Fatalf("post_start body: ${cfg.model} not substituted: got %q want %q", h.Body, want)
	}
	// ${host.data} is resolved by the darwin driver at apply time: it must
	// survive untouched (like ${host.gateway}) and not count as "unset".
	if got := hs.Env["OLLAMA_MODELS"]; got != "${host.data}/models" {
		t.Fatalf("${host.data} must stay literal, got %q", got)
	}
}

func TestBuildInstanceConfig_HostServicePostStartDefaultFromSchema(t *testing.T) {
	built, err := BuildInstanceConfig([]byte(ollamaV2Manifest), nil, "inst-1", "ollama-host", "")
	if err != nil {
		t.Fatalf("BuildInstanceConfig: %v", err)
	}
	raw, _ := json.Marshal(built.Config)
	if !strings.Contains(string(raw), `{\"model\":\"gemma3:4b\",\"stream\":false}`) {
		t.Fatalf("configSchema default not applied in post_start body: %s", raw)
	}
}

func TestBuildInstanceConfig_ContainerServiceReadiness(t *testing.T) {
	m := `
apiVersion: obacht.dev/v2
kind: Template
metadata:
  name: openwebui-mac
  version: "2.0.0"
spec:
  minSpecVersion: "v2.9"
  runtime:
    type: container
    container:
      image: ghcr.io/open-webui/open-webui:v0.11.3
      env:
        OLLAMA_BASE_URL: "http://${host.gateway}:11434"
      network: obacht-edge
  services:
    - name: web
      targetType: container_port
      targetPort: 8080
      readiness:
        path: /health
        expectStatus: [200, 204]
        timeoutSeconds: 900
`
	built, err := BuildInstanceConfig([]byte(m), nil, "inst-1", "openwebui-mac", "")
	if err != nil {
		t.Fatalf("BuildInstanceConfig: %v", err)
	}
	raw, _ := json.Marshal(built.Config)
	var out struct {
		Env      map[string]string `json:"env"`
		Services []struct {
			Name      string `json:"name"`
			Readiness *struct {
				Path           string `json:"path"`
				ExpectStatus   []int  `json:"expectStatus"`
				TimeoutSeconds int    `json:"timeoutSeconds"`
			} `json:"readiness"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Services) != 1 || out.Services[0].Readiness == nil {
		t.Fatalf("services[].readiness dropped: %s", raw)
	}
	r := out.Services[0].Readiness
	if r.Path != "/health" || r.TimeoutSeconds != 900 || len(r.ExpectStatus) != 2 || r.ExpectStatus[1] != 204 {
		t.Fatalf("readiness not carried through: %+v", r)
	}
	if out.Env["OLLAMA_BASE_URL"] != "http://${host.gateway}:11434" {
		t.Fatalf("${host.gateway} must stay literal: %q", out.Env["OLLAMA_BASE_URL"])
	}
}

func TestBuildInstanceConfig_ComposeServiceReadiness(t *testing.T) {
	m := `
apiVersion: obacht.dev/v2
kind: Template
metadata:
  name: ghost-bundle
  version: "1.1.0"
spec:
  minSpecVersion: "v2.9"
  runtime:
    type: compose
    compose:
      primaryService: ghost
      primaryPort: 2368
      imageDigests:
        ghost:5: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      body: |
        services:
          ghost:
            image: ghost:5
  services:
    - name: web
      targetService: ghost
      targetPort: 2368
      readiness:
        path: /ghost/
        timeoutSeconds: 120
`
	built, err := BuildInstanceConfig([]byte(m), nil, "ghost-1", "ghost-bundle", "")
	if err != nil {
		t.Fatalf("BuildInstanceConfig: %v", err)
	}
	raw, _ := json.Marshal(built.Config)
	var out struct {
		Services []struct {
			Readiness *struct {
				Path           string `json:"path"`
				TimeoutSeconds int    `json:"timeoutSeconds"`
			} `json:"readiness"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Services) != 1 || out.Services[0].Readiness == nil || out.Services[0].Readiness.Path != "/ghost/" || out.Services[0].Readiness.TimeoutSeconds != 120 {
		t.Fatalf("compose services[].readiness dropped: %s", raw)
	}
}

func TestBuildInstanceConfig_SystemServiceReadiness(t *testing.T) {
	m := `
apiVersion: obacht.dev/v2
kind: Template
metadata:
  name: camera-streamer
  version: "1.1.0"
spec:
  minSpecVersion: "v2.9"
  runtime:
    type: system
    system:
      managed_service:
        binary: mediamtx
        binary_url: https://github.com/bluenviron/mediamtx/releases/download/v1.0.0/mediamtx.tar.gz
        binary_digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        archive: tgz
  services:
    - name: web
      targetType: host_port
      targetPort: 8888
      readiness:
        path: /cam/
`
	built, err := BuildInstanceConfig([]byte(m), nil, "cam-1", "camera-streamer", "")
	if err != nil {
		t.Fatalf("BuildInstanceConfig: %v", err)
	}
	raw, _ := json.Marshal(built.Config)
	if !strings.Contains(string(raw), `"readiness":{"path":"/cam/"}`) {
		t.Fatalf("system services[].readiness dropped: %s", raw)
	}
}
