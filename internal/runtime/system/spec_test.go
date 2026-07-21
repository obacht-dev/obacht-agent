package system

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, s Spec) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func validManaged() *ManagedServiceSpec {
	return &ManagedServiceSpec{
		Kind:         "mediamtx",
		Binary:       "mediamtx",
		BinaryURL:    "https://github.com/bluenviron/mediamtx/releases/download/v1/m.tar.gz",
		BinaryDigest: "sha256:" + strings.Repeat("a", 64),
		Archive:      "tgz",
	}
}

func TestValidate_WithdrawnFlavorRejected(t *testing.T) {
	// The pre-v2.8 free-form systemd flavor must be rejected explicitly, in
	// every combination.
	specs := []Spec{
		{UnitName: "obacht-foo.service", UnitTemplate: "[Service]\nExecStart=/bin/true\n"},
		{UnitName: "obacht-foo.service"},
		{UnitTemplate: "[Service]\nExecStart=/bin/true\n"},
		{UnitName: "x.service", ManagedService: validManaged()},
	}
	for i, s := range specs {
		err := s.Validate()
		if err == nil {
			t.Errorf("spec %d: withdrawn flavor accepted", i)
			continue
		}
		if !strings.Contains(err.Error(), "withdrawn") {
			t.Errorf("spec %d: expected withdrawn error, got %v", i, err)
		}
	}
}

func TestValidate_ExactlyOneFlavor(t *testing.T) {
	if err := (Spec{}).Validate(); err == nil {
		t.Error("empty spec accepted")
	}
	both := Spec{
		HostService:    &HostServiceSpec{Kind: "ollama", Binary: "ollama", BinaryURL: "https://ollama.com/x", BinaryDigest: "sha256:" + strings.Repeat("a", 64)},
		ManagedService: validManaged(),
	}
	if err := both.Validate(); err == nil {
		t.Error("spec with two flavors accepted")
	}
	if err := (Spec{ManagedService: validManaged()}).Validate(); err != nil {
		t.Errorf("valid managed spec rejected: %v", err)
	}
}

func TestValidate_ManagedServiceRules(t *testing.T) {
	mutate := func(fn func(*ManagedServiceSpec)) Spec {
		ms := validManaged()
		fn(ms)
		return Spec{ManagedService: ms}
	}
	cases := map[string]Spec{
		"binary not allowlisted": mutate(func(m *ManagedServiceSpec) { m.Binary = "bash" }),
		"binary traversal":       mutate(func(m *ManagedServiceSpec) { m.Binary = "../bash" }),
		"http url":               mutate(func(m *ManagedServiceSpec) { m.BinaryURL = "http://github.com/x" }),
		"foreign host":           mutate(func(m *ManagedServiceSpec) { m.BinaryURL = "https://evil.example/x" }),
		"bad digest":             mutate(func(m *ManagedServiceSpec) { m.BinaryDigest = "sha256:short" }),
		"uppercase digest":       mutate(func(m *ManagedServiceSpec) { m.BinaryDigest = "sha256:" + strings.Repeat("A", 64) }),
		"zip archive":            mutate(func(m *ManagedServiceSpec) { m.Archive = "zip" }),
		"arg control char":       mutate(func(m *ManagedServiceSpec) { m.Args = []string{"a\nb"} }),
		"env eq in key":          mutate(func(m *ManagedServiceSpec) { m.Env = map[string]string{"A=B": "c"} }),
		"foreign group":          mutate(func(m *ManagedServiceSpec) { m.Hardware = &ManagedHardware{Groups: []string{"docker"}} }),
		"foreign device":         mutate(func(m *ManagedServiceSpec) { m.Hardware = &ManagedHardware{Devices: []string{"/dev/sda"}} }),
		"port out of range":      mutate(func(m *ManagedServiceSpec) { m.ListenPorts = []int{70000} }),
	}
	for label, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
	ok := mutate(func(m *ManagedServiceSpec) {
		m.Args = []string{"/etc/obacht/svc/i/mediamtx.yml"}
		m.Env = map[string]string{"MTX_LOGLEVEL": "info"}
		m.Hardware = &ManagedHardware{Groups: []string{"video"}, Devices: []string{"/dev/video*", "/dev/media*"}}
		m.ListenPorts = []int{8888}
	})
	if err := ok.Validate(); err != nil {
		t.Errorf("full valid managed spec rejected: %v", err)
	}
}

func TestValidate_RejectsBadFilePaths(t *testing.T) {
	bad := []string{
		"/etc/sudoers.d/x",
		"/etc/cron.d/x",
		"/root/.ssh/authorized_keys",
		"relative/path",
		"/etc/obacht/../../root/x", // traversal (non-canonical)
		"/etc/obacht//x",           // non-canonical
		"/etc/obacht-evil/x",       // prefix on non-segment boundary
		"/var/lib/obacht/x\x00y",   // NUL
		"/opt/obacht/x\n",          // newline
	}
	for _, p := range bad {
		s := Spec{
			ManagedService: validManaged(),
			Files:          []File{{Path: p, Content: "x"}},
		}
		if err := s.Validate(); err == nil {
			t.Errorf("expected file path %q to be rejected", p)
		}
	}
}

func TestValidate_AcceptsGoodFilePaths(t *testing.T) {
	good := []string{
		"/etc/obacht/svc/inst/config.yaml",
		"/opt/obacht/svc/inst/data.json",
	}
	for _, p := range good {
		s := Spec{
			ManagedService: validManaged(),
			Files:          []File{{Path: p, Content: "x"}},
		}
		if err := s.Validate(); err != nil {
			t.Errorf("expected file path %q to be accepted, got %v", p, err)
		}
	}
}

func TestParseSpec_ValidatesThroughParse(t *testing.T) {
	cfg := mustJSON(t, Spec{
		ManagedService: validManaged(),
		Files:          []File{{Path: "/etc/passwd", Content: "pwned"}},
	})
	if _, err := ParseSpec(cfg); err == nil {
		t.Fatal("expected ParseSpec to reject /etc/passwd file path")
	} else if !strings.Contains(err.Error(), "allowed prefixes") {
		t.Fatalf("unexpected error: %v", err)
	}
}
