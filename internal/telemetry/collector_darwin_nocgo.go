//go:build darwin && !cgo

package telemetry

import "golang.org/x/sys/unix"

// Cgo-free macOS collector (e.g. CGO_ENABLED=0 cross-compiles): disk, total RAM
// and network addresses only. CPU% and used RAM need Mach (cgo) — see
// collector_darwin_cgo.go, used by native macOS builds.
func NewCollector() Collector { return &darwinCollector{} }

type darwinCollector struct {
	net netInfo
}

func (c *darwinCollector) Collect() (Sample, error) {
	s := Sample{}
	if total, err := unix.SysctlUint64("hw.memsize"); err == nil && total > 0 {
		s.RAMTotal = &total
	}
	if used, total, err := readDisk("/"); err == nil {
		s.DiskUsed = &used
		s.DiskTotal = &total
	}
	s.WireguardIP, s.LocalIP, s.PublicIP = c.net.collect()
	return s, nil
}
