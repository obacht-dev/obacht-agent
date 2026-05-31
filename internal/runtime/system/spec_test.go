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

func TestValidate_RejectsUnitNameTraversal(t *testing.T) {
	bad := []string{
		"../../etc/cron.d/evil.service",
		"evil",                 // no .service suffix
		"evil.timer",           // wrong suffix
		"/etc/evil.service",    // leading slash / path
		"sub/dir/evil.service", // path separator
		"evil.service\n",       // control char
		"",
	}
	for _, name := range bad {
		s := Spec{UnitName: name, UnitTemplate: "[Service]\nExecStart=/bin/true\n"}
		if err := s.Validate(); err == nil {
			t.Errorf("expected unit name %q to be rejected", name)
		}
	}
}

func TestValidate_AcceptsGoodUnitName(t *testing.T) {
	for _, name := range []string{"obacht-foo.service", "foo@bar.service", "a_b.c-d.service"} {
		s := Spec{UnitName: name, UnitTemplate: "[Service]\nExecStart=/bin/true\n"}
		if err := s.Validate(); err != nil {
			t.Errorf("expected unit name %q to be accepted, got %v", name, err)
		}
	}
}

func TestValidate_RejectsBadFilePaths(t *testing.T) {
	bad := []string{
		"/etc/sudoers.d/x",
		"/etc/cron.d/x",
		"/root/.ssh/authorized_keys",
		"relative/path",
		"/etc/obacht/../../root/x",   // traversal (non-canonical)
		"/etc/obacht//x",             // non-canonical
		"/etc/obacht-evil/x",         // prefix on non-segment boundary
		"/var/lib/obacht/x\x00y",     // NUL
		"/opt/obacht/x\n",            // newline
	}
	for _, p := range bad {
		s := Spec{
			UnitName:     "ok.service",
			UnitTemplate: "[Service]\nExecStart=/bin/true\n",
			Files:        []File{{Path: p, Content: "x"}},
		}
		if err := s.Validate(); err == nil {
			t.Errorf("expected file path %q to be rejected", p)
		}
	}
}

func TestValidate_AcceptsGoodFilePaths(t *testing.T) {
	good := []string{
		"/etc/obacht/system/inst/config.yaml",
		"/var/lib/obacht/inst/data.json",
		"/opt/obacht/bin/helper",
	}
	for _, p := range good {
		s := Spec{
			UnitName:     "ok.service",
			UnitTemplate: "[Service]\nExecStart=/bin/true\n",
			Files:        []File{{Path: p, Content: "x"}},
		}
		if err := s.Validate(); err != nil {
			t.Errorf("expected file path %q to be accepted, got %v", p, err)
		}
	}
}

func TestParseSpec_ValidatesThroughParse(t *testing.T) {
	cfg := mustJSON(t, Spec{
		UnitName:     "ok.service",
		UnitTemplate: "[Service]\nExecStart=/bin/true\n",
		Files:        []File{{Path: "/etc/passwd", Content: "pwned"}},
	})
	if _, err := ParseSpec(cfg); err == nil {
		t.Fatal("expected ParseSpec to reject /etc/passwd file path")
	} else if !strings.Contains(err.Error(), "allowed prefixes") {
		t.Fatalf("unexpected error: %v", err)
	}
}
