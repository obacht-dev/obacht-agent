package system

import (
	"strings"
	"testing"
)

const validDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validHostService() *HostServiceSpec {
	return &HostServiceSpec{
		Kind:         "ollama",
		Binary:       "ollama",
		BinaryURL:    "https://ollama.com/download/ollama-darwin",
		BinaryDigest: validDigest,
		Args:         []string{"serve"},
		Env:          map[string]string{"OLLAMA_HOST": "192.168.64.1:11434"},
	}
}

func TestHostServiceSpec_Valid(t *testing.T) {
	s := Spec{HostService: validHostService()}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid host-service spec rejected: %v", err)
	}
}

func TestHostServiceSpec_Rejections(t *testing.T) {
	cases := map[string]func(h *HostServiceSpec){
		"binary not allowlisted":  func(h *HostServiceSpec) { h.Binary = "curl" },
		"binary with path sep":    func(h *HostServiceSpec) { h.Binary = "../ollama" },
		"missing url":             func(h *HostServiceSpec) { h.BinaryURL = "" },
		"missing digest":          func(h *HostServiceSpec) { h.BinaryDigest = "" },
		"bad digest prefix":       func(h *HostServiceSpec) { h.BinaryDigest = "md5:abcd" },
		"short digest":            func(h *HostServiceSpec) { h.BinaryDigest = "sha256:dead" },
		"non-https url":           func(h *HostServiceSpec) { h.BinaryURL = "http://ollama.com/x" },
		"disallowed host":         func(h *HostServiceSpec) { h.BinaryURL = "https://evil.example/x" },
		"control char in arg":     func(h *HostServiceSpec) { h.Args = []string{"serve\n--secret"} },
		"control char in env val": func(h *HostServiceSpec) { h.Env = map[string]string{"K": "v\ninjected"} },
		"equals in env key":       func(h *HostServiceSpec) { h.Env = map[string]string{"K=evil": "v"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := validHostService()
			mutate(h)
			if err := (Spec{HostService: h}).Validate(); err == nil {
				t.Fatalf("expected rejection for %q, got nil", name)
			}
		})
	}
}

func TestParseSpec_HostServiceRoundTrip(t *testing.T) {
	json := `{"host_service":{"kind":"ollama","binary":"ollama",` +
		`"binary_url":"https://github.com/ollama/ollama/releases/download/v0.1/ollama-darwin",` +
		`"binary_digest":"` + validDigest + `","args":["serve"],` +
		`"env":{"OLLAMA_HOST":"192.168.64.1:11434"}}}`
	s, err := ParseSpec(json)
	if err != nil {
		t.Fatalf("ParseSpec host-service: %v", err)
	}
	if s.HostService == nil || s.HostService.Binary != "ollama" {
		t.Fatalf("host service not parsed: %+v", s)
	}
	if s.UnitName != "" {
		t.Fatalf("host-service spec should have no unit name, got %q", s.UnitName)
	}
}

// The pre-v2.8 free-form systemd flavor is withdrawn: any spec carrying
// unit_name/unit_template must be rejected explicitly (never silently
// ignored), regardless of how well-formed it looks.
func TestSystemdSpec_WithdrawnFlavorRejected(t *testing.T) {
	legacy := Spec{UnitName: "obacht-x.service", UnitTemplate: "[Unit]\n[Service]\nExecStart=/bin/true\n"}
	if err := legacy.Validate(); err == nil || !strings.Contains(err.Error(), "withdrawn") {
		t.Fatalf("expected withdrawn rejection, got %v", err)
	}
}
