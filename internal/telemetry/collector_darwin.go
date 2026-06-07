//go:build darwin

package telemetry

import "golang.org/x/sys/unix"

// NewCollector returns a macOS collector.
//
// Deliberately cgo-free (the whole agent is): disk, total RAM and the network
// addresses are read via syscalls/sysctl. CPU%, used RAM and CPU temperature
// need Mach (host_statistics/vm_statistics64) or the SMC, which require cgo — we
// omit them here to keep the agent cgo-free. The macOS app surfaces those live
// natively instead (it can call Mach directly).
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

// readDisk returns used/total bytes of the filesystem at path (root fs).
func readDisk(path string) (used, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	free := st.Bavail * bsize
	if free > total {
		free = total
	}
	return total - free, total, nil
}
