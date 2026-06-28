//go:build darwin

package ingress

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// localPortUpstream returns the Caddy reverse_proxy target for a host port on
// the Mac. Caddy runs in the VM, where `host.docker.internal` resolves to the
// VM itself — NOT the macOS host. So we target the VZ gateway (the macOS host as
// seen from the VM); a host-side forwarder (syncLocalPortForwarders) bridges
// gateway:<port> → 127.0.0.1:<port>. If the gateway isn't known yet, fall back
// to the docker host alias so we degrade instead of emitting a broken target.
func localPortUpstream(port int, gateway string) string {
	if gateway == "" {
		return fmt.Sprintf("host.docker.internal:%d", port)
	}
	return fmt.Sprintf("%s:%d", gateway, port)
}

// reservedHostPorts are never forwarded — obacht's own host plumbing. (The
// agent IPC, helper, and docker bridge are unix sockets, not TCP ports; other
// obacht host listeners bind distinct IPs. A user port that collides with a
// live listener simply fails net.Listen and is skipped + logged.)
var reservedHostPorts = map[int]bool{
	51820: true, // WireGuard
}

// syncLocalPortForwarders ensures exactly one forwarder per wanted local port
// and tears down ports no longer bound. Security properties:
//   - binds ONLY the VZ gateway interface (host↔VM bridge), never 0.0.0.0/LAN,
//     so the user's service is never exposed to the home network — only to the
//     VM (and, via the bound domain, the internet, which is the user's intent);
//   - only ports from user-signed bindings reach here (the allowlist), so this
//     opens nothing the user didn't explicitly bind;
//   - obacht-reserved ports are refused.
func (m *Manager) syncLocalPortForwarders(ports []int) {
	if m.hostGateway == "" {
		return // no VZ gateway known yet; nothing to bridge
	}
	want := map[int]bool{}
	for _, p := range ports {
		if p > 0 && p <= 65535 && !reservedHostPorts[p] {
			want[p] = true
		}
	}

	m.localProxyMu.Lock()
	defer m.localProxyMu.Unlock()
	if m.localProxies == nil {
		m.localProxies = map[int]io.Closer{}
	}
	// Stop forwarders that are no longer wanted.
	for p, c := range m.localProxies {
		if !want[p] {
			_ = c.Close()
			delete(m.localProxies, p)
			m.log.Info("local-port forwarder stopped", "port", p)
		}
	}
	// Start forwarders that are wanted but not yet running.
	for p := range want {
		if _, ok := m.localProxies[p]; ok {
			continue
		}
		f, err := startLocalForwarder(m.hostGateway, p, m.log)
		if err != nil {
			m.log.Warn("local-port forwarder start failed", "port", p, "err", err)
			continue
		}
		m.localProxies[p] = f
		m.log.Info("local-port forwarder started",
			"listen", fmt.Sprintf("%s:%d", m.hostGateway, p),
			"target", fmt.Sprintf("127.0.0.1:%d", p))
	}
}

type localForwarder struct{ ln net.Listener }

func (f *localForwarder) Close() error { return f.ln.Close() }

// startLocalForwarder listens on gateway:port (VZ interface only) and bridges
// each accepted connection to 127.0.0.1:port on the host.
func startLocalForwarder(gateway string, port int, log *slog.Logger) (io.Closer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", gateway, port))
	if err != nil {
		return nil, err
	}
	f := &localForwarder{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed (forwarder torn down)
			}
			go bridgeConn(conn, port)
		}
	}()
	return f, nil
}

// bridgeConn pipes a VM-side connection to the host loopback service. Dials
// "localhost" (not a hard 127.0.0.1) so it reaches dev servers that bind only
// IPv6 loopback [::1] — Node/Vite/Astro default to that, and an IPv4-only dial
// would refuse → Caddy 502. Still loopback-only (localhost never resolves off
// the host). If the service isn't running the dial fails and the connection
// closes — Caddy returns 502 rather than hanging.
func bridgeConn(client net.Conn, port int) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}
