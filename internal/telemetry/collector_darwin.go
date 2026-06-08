//go:build darwin

package telemetry

import "golang.org/x/sys/unix"

// Shared macOS helpers. NewCollector lives in collector_darwin_cgo.go (full
// metrics, native builds) and collector_darwin_nocgo.go (cgo-free fallback).

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
