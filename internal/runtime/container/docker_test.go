package container

import "testing"

func TestValidateBindSource(t *testing.T) {
	ws := "/var/lib/obacht/hoarder/inst-123"

	good := []string{
		"/var/lib/obacht/hoarder/inst-123",
		"/var/lib/obacht/hoarder/inst-123/data",
		"/var/lib/obacht/hoarder/inst-123/data/sub",
		"named-volume", // docker named volume, not a host path
		"my_data",      // named volume
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
		"/var/lib/obacht/other/inst-999/data", // another instance/template
		"/var/lib/obacht/hoarder/inst-123/../../../etc", // traversal escape
		"/var/lib/obacht/hoarder/inst-1234",             // sibling, prefix-not-segment
		"/var/lib/obacht/hoarder/inst-123-evil",         // prefix not on boundary
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

// Regression for the agent-v2 install break (≥ v0.3.18): the reconciler injects
// the IPC socket as an AgentManaged mount whose source (/run/obacht/agent-v2.sock)
// lives outside the instance workspace. The workspace-escape confinement added
// in 917fecd must not reject it, while still rejecting an equivalent mount that
// a manifest tries to declare itself.
func TestResolveBinds_AgentManagedSocketBypassesConfinement(t *testing.T) {
	ws := "/var/lib/obacht/actual-budget/actual-budget"
	vols := []VolumeMount{
		{Source: ws + "/data", Target: "/data"},
		{Source: "/run/obacht/agent-v2.sock", Target: "/run/obacht/agent.sock", AgentManaged: true},
	}
	binds, preCreate, err := resolveBinds(ws, vols)
	if err != nil {
		t.Fatalf("agent-managed socket mount must not be rejected, got %v", err)
	}
	want := []string{
		ws + "/data:/data:rw",
		"/run/obacht/agent-v2.sock:/run/obacht/agent.sock:rw",
	}
	if len(binds) != len(want) {
		t.Fatalf("binds = %v, want %v", binds, want)
	}
	for i := range want {
		if binds[i] != want[i] {
			t.Errorf("binds[%d] = %q, want %q", i, binds[i], want[i])
		}
	}
	// Only the real workspace dir is pre-created; the socket file must never be
	// MkdirAll'd (it would fail on / clobber the existing socket).
	if len(preCreate) != 1 || preCreate[0] != ws+"/data" {
		t.Errorf("preCreateDirs = %v, want [%q]", preCreate, ws+"/data")
	}
}

func TestResolveBinds_NonAgentEscapeStillRejected(t *testing.T) {
	ws := "/var/lib/obacht/actual-budget/actual-budget"
	// A manifest cannot smuggle the socket past confinement: AgentManaged is
	// json:"-" so it can't be set from manifest JSON, and without it the source
	// escapes the workspace and must be rejected.
	vols := []VolumeMount{{Source: "/run/obacht/agent-v2.sock", Target: "/x"}}
	if _, _, err := resolveBinds(ws, vols); err == nil {
		t.Error("non-agent mount escaping the workspace must be rejected")
	}
}
