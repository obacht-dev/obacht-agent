// Package compat detects properties of the host the agent is running on so
// the api can compare them against a manifest's spec.compatibility block.
//
// Reads:
//   - /proc/device-tree/model           (e.g. "Raspberry Pi 5 Model B Rev 1.0")
//   - /etc/os-release                   (ID, VERSION_ID)
//   - /proc/meminfo                     (MemTotal)
//   - statfs of dataRoot                (free disk for the agent's data dir)
//   - /sys/class/dmi/id/{sys_vendor,...} (fixed allowlist, see dmiFiles)
//
// Falls back to runtime.GOOS/GOARCH on non-Linux. Intended to be cheap and
// called once at startup; the result is stable for the host's lifetime.
package compat

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// Paths are vars so tests can point them at fixture dirs.
var (
	deviceTreeModel = "/proc/device-tree/model"
	dmiRoot         = "/sys/class/dmi/id"
)

// Identity is what the agent reports to the api. The api echoes the same
// shape back inside install plans for the compatibility check.
type Identity struct {
	Device       string `json:"device"`       // e.g. "raspberry-pi-5"
	Architecture string `json:"architecture"` // e.g. "linux/arm64"
	OSID         string `json:"os_id"`        // /etc/os-release ID, lower-case
	OSVersion    string `json:"os_version"`   // /etc/os-release VERSION_ID
	RamTotalMb   int    `json:"ram_total_mb"`
	DiskFreeMb   int    `json:"disk_free_mb"`
	// Hardware is display-only (device illustrations). Never used for
	// template gating; that stays on Device. Nil when nothing was found.
	Hardware *Hardware `json:"hardware,omitempty"`
}

// Hardware describes what the box is, for picking an illustration. It
// deliberately carries nothing that identifies a single unit: no serials,
// no UUIDs, no asset tags.
type Hardware struct {
	Model       string `json:"model"`        // /proc/device-tree/model, e.g. "Raspberry Pi 400 Rev 1.0"
	Vendor      string `json:"vendor"`       // DMI sys_vendor
	Product     string `json:"product"`      // DMI product_name (cryptic on Lenovo: "10T7S0AX00")
	Version     string `json:"version"`      // DMI product_version (readable on Lenovo: "ThinkCentre M920q")
	Family      string `json:"family"`       // DMI product_family
	BoardVendor string `json:"board_vendor"` // DMI board_vendor
	BoardName   string `json:"board_name"`   // DMI board_name
	Chassis     int    `json:"chassis"`      // SMBIOS chassis type, 0 if unknown
	Virtual     bool   `json:"virtual"`
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
	id.Hardware = detectHardware()
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
	if b, err := os.ReadFile(deviceTreeModel); err == nil {
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

// dmiFiles is the complete list of DMI attributes the agent reads. Data
// minimisation: no glob over dmiRoot, and never product_serial,
// product_uuid, board_serial, chassis_serial or *_asset_tag, even when
// running with rights that would allow it.
var dmiFiles = [...]string{
	"sys_vendor",
	"product_name",
	"product_version",
	"product_family",
	"chassis_type",
	"board_vendor",
	"board_name",
}

// maxHardwareRunes caps every hardware string.
const maxHardwareRunes = 64

// biosPlaceholders are filler values vendors leave in DMI. Compared
// case-insensitively after cleaning; a match becomes "".
var biosPlaceholders = map[string]bool{
	"default string":         true,
	"to be filled by o.e.m.": true,
	"system manufacturer":    true,
	"system product name":    true,
	"system version":         true,
	"not applicable":         true,
	"none":                   true,
	"n/a":                    true,
	"0123456789":             true,
	"type1productconfigid":   true,
	"oem":                    true,
	"o.e.m.":                 true,
	"not specified":          true,
}

// virtualMarkers flag a hypervisor when found (case-insensitive) in
// vendor or product.
var virtualMarkers = []string{
	"qemu", "kvm", "vmware", "virtualbox", "innotek", "xen", "bochs",
	"parallels", "apple virtualization", "amazon ec2",
	"google compute engine", "digitalocean", "droplet", "openstack",
}

// detectHardware reads the device-tree model and the DMI allowlist.
// Best effort, unprivileged, no exec. Returns nil when nothing was found
// (e.g. on darwin, or a board without device tree or DMI).
func detectHardware() *Hardware {
	dmi := readDMI()
	hw := &Hardware{
		Model:       cleanHardwareString(readSmall(deviceTreeModel)),
		Vendor:      dmi["sys_vendor"],
		Product:     dmi["product_name"],
		Version:     dmi["product_version"],
		Family:      dmi["product_family"],
		BoardVendor: dmi["board_vendor"],
		BoardName:   dmi["board_name"],
	}
	if n, err := strconv.Atoi(dmi["chassis_type"]); err == nil && n > 0 && n <= 255 {
		hw.Chassis = n
	}
	hw.Virtual = isVirtual(hw.Vendor, hw.Product)
	if *hw == (Hardware{}) {
		return nil
	}
	return hw
}

// readDMI returns the cleaned values of dmiFiles that exist. Missing or
// unreadable files (some are root-only on older kernels) are skipped.
func readDMI() map[string]string {
	out := make(map[string]string, len(dmiFiles))
	for _, name := range dmiFiles {
		if v := cleanHardwareString(readSmall(filepath.Join(dmiRoot, name))); v != "" {
			out[name] = v
		}
	}
	return out
}

// readSmall reads at most 4 KiB; sysfs and device-tree values are tiny.
func readSmall(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return ""
	}
	return string(b)
}

// cleanHardwareString trims, maps whitespace to single spaces, drops NUL
// and other non-printable runes, blanks BIOS placeholders and caps the
// result at maxHardwareRunes.
func cleanHardwareString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// invalid UTF-8, drop
		case unicode.IsSpace(r):
			b.WriteRune(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if biosPlaceholders[strings.ToLower(out)] {
		return ""
	}
	if utf8.RuneCountInString(out) > maxHardwareRunes {
		out = strings.TrimSpace(string([]rune(out)[:maxHardwareRunes]))
	}
	return out
}

func isVirtual(vendor, product string) bool {
	v, p := strings.ToLower(vendor), strings.ToLower(product)
	for _, m := range virtualMarkers {
		if strings.Contains(v, m) || strings.Contains(p, m) {
			return true
		}
	}
	switch {
	case strings.Contains(v, "microsoft corporation") && strings.Contains(p, "virtual machine"):
		return true // Hyper-V / Azure
	case strings.Contains(v, "hetzner") && strings.Contains(p, "vserver"):
		return true
	}
	return false
}
