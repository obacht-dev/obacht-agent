//go:build !darwin

package ingress

import "testing"

// Locks the Pi/fleet behavior: a local-port binding must ALWAYS render to
// host.docker.internal on non-macOS, regardless of any gateway value. If this
// ever changes, a fleet-wide agent release would break Pi local-port proxies.
func TestLocalPortUpstream_NonDarwin(t *testing.T) {
	if got := localPortUpstream(8080, ""); got != "host.docker.internal:8080" {
		t.Fatalf("no gateway: got %q, want host.docker.internal:8080", got)
	}
	if got := localPortUpstream(3000, "192.168.64.1"); got != "host.docker.internal:3000" {
		t.Fatalf("gateway must be ignored on non-darwin: got %q, want host.docker.internal:3000", got)
	}
}
