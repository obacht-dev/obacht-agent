// Package compat detects properties of the host the agent is running on so
// the api can compare them against a manifest's spec.compatibility block.
//
// Reads:
//   - /proc/device-tree/model           (e.g. "Raspberry Pi 5 Model B Rev 1.0")
//   - /etc/os-release                   (ID, VERSION_ID)
//   - /proc/meminfo                     (MemTotal)
//   - statfs of dataRoot                (free disk for the agent's data dir)
//
// Falls back to runtime.GOOS/GOARCH on non-Linux. Intended to be cheap and
// called once at startup; the result is stable for the host's lifetime.
package compat

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Identity is what the agent reports to the api. The api echoes the same
// shape back inside install plans for the compatibility check.
type Identity struct {
	Device       string `json:"device"`        // e.g. "raspberry-pi-5"
	Architecture string `json:"architecture"`  // e.g. "linux/arm64"
	OSID         string `json:"os_id"`         // /etc/os-release ID, lower-case
	OSVersion    string `json:"os_version"`    // /etc/os-release VERSION_ID
	RamTotalMb   int    `json:"ram_total_mb"`
	DiskFreeMb   int    `json:"disk_free_mb"`
}

// Detect populates an Identity. Best-effort: missing fields stay empty.
func Detect(dataRoot string) Identity {
	id := Identity{
		Architecture: arch(),
	}
	id.Device = detectDevice()
	id.OSID, id.OSVersion = readOSRelease()
	id.RamTotalMb = readRamTotalMb()
	id.DiskFreeMb = readDiskFreeMb(dataRoot)
	return id
}

func arch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "linux/arm64"
	case "amd64":
		return "linux/amd64"
	case "arm":
		return "linux/arm/v7"
	default:
		return runtime.GOOS + "/" + runtime.GOARCH
	}
}

func detectDevice() string {
	if b, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		// device-tree includes a trailing NUL; trim it.
		model := strings.TrimRight(strings.TrimSpace(string(b)), "\x00")
		switch {
		case strings.Contains(model, "Raspberry Pi 5"):
			return "raspberry-pi-5"
		case strings.Contains(model, "Raspberry Pi 4"):
			return "raspberry-pi-4"
		}
	}
	switch runtime.GOARCH {
	case "arm64":
		return "generic-arm64"
	case "amd64":
		return "generic-x86_64"
	}
	return ""
}

func readOSRelease() (id, ver string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			ver = v
		}
	}
	return id, ver
}

func readRamTotalMb() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, _ := strconv.Atoi(fields[1])
			return kb / 1024
		}
	}
	return 0
}

func readDiskFreeMb(path string) int {
	if path == "" {
		return 0
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	// Bavail is for unprivileged users, but we run as root; either is fine.
	free := uint64(stat.Bsize) * stat.Bavail
	return int(free / (1024 * 1024))
}
