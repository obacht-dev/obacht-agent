//go:build darwin

package ingress

import "testing"

// On the Mac the upstream targets the VZ gateway (Caddy in the VM can't reach
// the host via host.docker.internal); with no gateway known yet it falls back
// to the docker host alias rather than emitting a broken target.
func TestLocalPortUpstream_Darwin(t *testing.T) {
	if got := localPortUpstream(3000, "192.168.64.1"); got != "192.168.64.1:3000" {
		t.Fatalf("with gateway: got %q, want 192.168.64.1:3000", got)
	}
	if got := localPortUpstream(3000, ""); got != "host.docker.internal:3000" {
		t.Fatalf("no gateway (fallback): got %q, want host.docker.internal:3000", got)
	}
}

func TestReservedHostPortsNotForwarded(t *testing.T) {
	m := &Manager{hostGateway: "192.168.64.1"}
	// 51820 (WireGuard) is reserved → must not get a forwarder.
	m.syncLocalPortForwarders([]int{51820})
	if len(m.localProxies) != 0 {
		t.Fatalf("reserved port was forwarded: %v", m.localProxies)
	}
}
