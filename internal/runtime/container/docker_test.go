package container

import "testing"

func TestValidateBindSource(t *testing.T) {
	ws := "/var/lib/obacht/hoarder/inst-123"

	good := []string{
		"/var/lib/obacht/hoarder/inst-123",
		"/var/lib/obacht/hoarder/inst-123/data",
		"/var/lib/obacht/hoarder/inst-123/data/sub",
		"named-volume",     // docker named volume, not a host path
		"my_data",          // named volume
	}
	for _, s := range good {
		if err := validateBindSource(ws, s); err != nil {
			t.Errorf("expected source %q to be accepted, got %v", s, err)
		}
	}

	bad := []string{
		"",
		"/",
		"/etc/shadow",
		"/var/run/docker.sock",
		"/var/lib/obacht/other/inst-999/data",  // another instance/template
		"/var/lib/obacht/hoarder/inst-123/../../../etc", // traversal escape
		"/var/lib/obacht/hoarder/inst-1234",    // sibling, prefix-not-segment
		"/var/lib/obacht/hoarder/inst-123-evil", // prefix not on boundary
		"/var/lib/obacht/hoarder/inst-123\x00/x",
	}
	for _, s := range bad {
		if err := validateBindSource(ws, s); err == nil {
			t.Errorf("expected source %q to be rejected", s)
		}
	}
}

func TestValidateBindSource_DegenerateWorkspace(t *testing.T) {
	// Empty template/instance id must not collapse the confinement to the root.
	if err := validateBindSource("/var/lib/obacht", "/var/lib/obacht/anything"); err == nil {
		t.Error("expected degenerate workspace to be rejected")
	}
}
