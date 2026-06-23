// Package diskcheck guards installs against a near-full device. Pulling a
// container image onto a filesystem with almost no space left fails partway
// with a cryptic ENOSPC and can leave half-written layers behind. A cheap
// statfs preflight before the pull turns that into an immediate, legible
// error the reconciler can record as the instance's observed state — so the
// webapp shows "insufficient disk space" instead of the install silently
// churning and failing mid-stream.
package diskcheck

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// DefaultMinFreeBytes is the floor of free space required before the agent
// will pull an image for a new install or an update. 2 GiB comfortably covers
// a typical template image (a few hundred MB–1 GB once unpacked) plus runtime
// scratch, while still refusing on a device that is essentially full.
const DefaultMinFreeBytes uint64 = 2 << 30

// MinFreeBytesEnv overrides the floor (in bytes) for operators running
// unusually large (or small) templates.
const MinFreeBytesEnv = "OBACHT_MIN_FREE_DISK_BYTES"

// MinFreeBytes returns the configured free-space floor.
func MinFreeBytes() uint64 {
	if v := os.Getenv(MinFreeBytesEnv); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return DefaultMinFreeBytes
}

// FreeBytes reports the bytes available to the agent on the filesystem holding
// path. ok is false when the filesystem can't be queried (e.g. path missing
// because dockerd lives in a VM on macOS and the Linux data root does not
// exist on the host) — callers should then fail open and skip the guard rather
// than block an install on a quirk.
func FreeBytes(path string) (free uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bsize) * st.Bavail, true
}

// EnsureFree returns a descriptive error when the filesystem holding path has
// less than the configured floor available. It fails OPEN — returns nil — when
// free space can't be determined, so an unrelated statfs quirk never blocks an
// install. path must be a directory on the same filesystem images land on.
func EnsureFree(path string) error {
	free, ok := FreeBytes(path)
	if !ok {
		return nil
	}
	min := MinFreeBytes()
	if free >= min {
		return nil
	}
	return fmt.Errorf("insufficient disk space: %s free, need at least %s — free up space and retry",
		humanize(free), humanize(min))
}

func humanize(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
