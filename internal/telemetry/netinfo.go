package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// publicIPTTL bounds how often the (relatively expensive) external public-IP
// lookup runs. wireguard/local addresses are cheap syscalls and refreshed on
// every Collect.
const publicIPTTL = 10 * time.Minute

// netInfo caches the device's discovered network addresses. The public IP is
// fetched from an external echo service at most once per publicIPTTL; the
// wireguard and LAN addresses are recomputed on every call.
type netInfo struct {
	mu            sync.Mutex
	publicIP      string
	publicFetched time.Time
}

// collect returns the device's wireguard IP (wg0), primary LAN IPv4, and the
// ISP-assigned public IP. Any value that can't be determined is returned as a
// nil pointer so it is omitted from the telemetry payload.
func (n *netInfo) collect() (wg, local, public *string) {
	if v := wireguardIP(); v != "" {
		wg = &v
	}
	if v := localIP(); v != "" {
		local = &v
	}
	if v := n.cachedPublicIP(); v != "" {
		public = &v
	}
	return
}

func (n *netInfo) cachedPublicIP() string {
	n.mu.Lock()
	if n.publicIP != "" && time.Since(n.publicFetched) < publicIPTTL {
		v := n.publicIP
		n.mu.Unlock()
		return v
	}
	n.mu.Unlock()

	if v := fetchPublicIP(); v != "" {
		n.mu.Lock()
		n.publicIP = v
		n.publicFetched = time.Now()
		n.mu.Unlock()
		return v
	}

	// Lookup failed (offline, rate-limited) — fall back to the last known
	// value, which may be empty on first run.
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.publicIP
}

// obachtWGNet is the obacht WireGuard mesh supernet. The device's address on it
// is the "Obacht Network IP". It lives on wg0 (Linux/Pi) or a utunN (macOS), so
// we detect it by range rather than by interface name.
var obachtWGNet = mustCIDR("10.137.0.0/16")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// wireguardIP returns the device's IPv4 on the obacht WireGuard mesh, or "".
// Scans interfaces for an address in obachtWGNet so it works for both the Pi's
// wg0 and the Mac's utun (the tunnel must be up).
func wireguardIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip := ipv4Of(a); ip != "" && obachtWGNet.Contains(net.ParseIP(ip)) {
				return ip
			}
		}
	}
	return ""
}

// localIP returns the primary outbound LAN IPv4 by inspecting the route the
// kernel would use to reach a public address (no packets are actually sent).
// If that route resolves to the wireguard interface, it falls back to scanning
// for a private, non-wireguard interface address.
func localIP() string {
	if ip := outboundIP(); ip != "" && !isWireguardIP(ip) {
		return ip
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		if name == "wg0" ||
			strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ip := ipv4Of(a)
			if ip != "" && isPrivateIP(ip) {
				return ip
			}
		}
	}
	return outboundIP()
}

// outboundIP returns the local address the kernel would use for an outbound
// connection. The UDP "connect" sets up the route without sending packets.
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	return ""
}

// fetchPublicIP queries external echo services (in order) until one returns a
// parseable IP. Bounded by a short timeout so it never stalls the telemetry
// loop for long.
func fetchPublicIP() string {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://ifconfig.me/ip",
	}
	client := &http.Client{Timeout: 4 * time.Second}
	for _, endpoint := range endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		cancel()
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(body))
		if net.ParseIP(v) != nil {
			return v
		}
	}
	return ""
}

func ipv4Of(a net.Addr) string {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return ip4.String()
}

func isWireguardIP(ip string) bool {
	wg := wireguardIP()
	return wg != "" && wg == ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}
