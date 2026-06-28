//go:build !darwin

package ingress

import "fmt"

// localPortUpstream returns the Caddy reverse_proxy target for a host port.
//
// On non-macOS devices (the Pi/linux fleet) Caddy runs in a container on the
// same host as the user's service, so it reaches host ports through docker's
// `host.docker.internal:host-gateway` alias — exactly today's behavior. The
// gateway argument is ignored here; it only matters on the Mac (see the darwin
// build), where Caddy lives in a separate VM. Keeping this path unchanged is
// what makes the local-reverse-proxy feature Pi-safe.
func localPortUpstream(port int, gateway string) string {
	return fmt.Sprintf("host.docker.internal:%d", port)
}

// syncLocalPortForwarders is a no-op off macOS: the Pi reaches host ports
// directly via host.docker.internal, so no host-side forwarder is needed.
func (m *Manager) syncLocalPortForwarders(ports []int) {}
