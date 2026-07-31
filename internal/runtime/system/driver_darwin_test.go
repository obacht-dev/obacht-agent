package system

import (
	"strings"
	"testing"
)

// renderPlist must be byte-for-byte deterministic: the reconciler compares the
// rendered plist against the on-disk file every tick and RESTARTS the service
// on any difference. A map-ordered env render flapped the service permanently
// once a host_service had more than one env var.
func TestRenderPlistDeterministicEnvOrder(t *testing.T) {
	env := map[string]string{
		"OLLAMA_HOST":           "0.0.0.0:11434",
		"OLLAMA_CONTEXT_LENGTH": "16384",
		"ZZZ_LAST":              "z",
		"AAA_FIRST":             "a",
	}
	first := renderPlist("dev.obacht.hostsvc.test", "/bin/echo", []string{"serve"}, env, "/tmp/logs")
	for i := 0; i < 50; i++ {
		if got := renderPlist("dev.obacht.hostsvc.test", "/bin/echo", []string{"serve"}, env, "/tmp/logs"); got != first {
			t.Fatalf("renderPlist is not deterministic (iteration %d):\n--- first ---\n%s\n--- got ---\n%s", i, first, got)
		}
	}
	// Keys must come out sorted so the output is stable across processes too.
	iA := strings.Index(first, "AAA_FIRST")
	iC := strings.Index(first, "OLLAMA_CONTEXT_LENGTH")
	iH := strings.Index(first, "OLLAMA_HOST")
	iZ := strings.Index(first, "ZZZ_LAST")
	if !(iA < iC && iC < iH && iH < iZ) {
		t.Fatalf("env keys not sorted: positions AAA=%d CONTEXT=%d HOST=%d ZZZ=%d\n%s", iA, iC, iH, iZ, first)
	}
}
