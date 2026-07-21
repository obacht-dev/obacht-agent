// Package inventory detects device hardware/software the backend and clients
// use for template gating (spec v2.8 compatibility.requiresFeatures) and for
// device-inventory config selects (configField.optionsSource).
//
// Everything here is read-only, unprivileged and cheap: sysfs walks and
// fixed-path stats. No exec, no new privileges — the agent user does not
// need the video group to LIST cameras, only the workload needs it to open
// them (that grant flows through the managed-service unit).
package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Camera is one detected camera. ID is the value stored into the instance
// config when the user picks the camera (v1: the libcamera/CSI index as a
// bare digit string, so manifests can splice it directly into e.g.
// MediaMTX's rpiCameraCamID). Label is what clients render.
type Camera struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // "csi" (v1; usb webcams come later)
}

// Inventory is what the agent reports under `inventory` in agent:register.
// Keys mirror the spec's optionsSource inventory enum.
type Inventory struct {
	Cameras []Camera `json:"cameras"`
}

// sysfsVideo4linux is a var for tests.
var sysfsVideo4linux = "/sys/class/video4linux"

// csiSensorRe matches the sensor token of a CSI camera subdevice name, e.g.
// "imx477 10-001a" → "imx477", "ov5647 …" → "ov5647". The bcm2835/rp1 codec
// and ISP nodes never match this shape, which is exactly the filtering we
// need (verified against a Pi 4 with an HQ camera: 17 video4linux nodes, one
// sensor subdev).
var csiSensorRe = regexp.MustCompile(`^([a-z]{2,8}[0-9]{2,5})( |$)`)

// Collect gathers the device inventory. Non-Linux hosts report an empty
// inventory (Mac cameras are not template-addressable).
func Collect() Inventory {
	if runtime.GOOS != "linux" {
		return Inventory{}
	}
	return Inventory{Cameras: detectCSICameras()}
}

// detectCSICameras enumerates CSI camera sensors via v4l subdevice names.
// The index assigned here follows the sorted subdevice order, which matches
// libcamera's enumeration on single-camera setups (the overwhelmingly common
// case); multi-camera index mapping is revisited when a template needs it.
func detectCSICameras() []Camera {
	entries, err := os.ReadDir(sysfsVideo4linux)
	if err != nil {
		return nil
	}
	var subdevs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "v4l-subdev") {
			subdevs = append(subdevs, e.Name())
		}
	}
	sort.Strings(subdevs)

	var cams []Camera
	for _, sd := range subdevs {
		raw, err := os.ReadFile(filepath.Join(sysfsVideo4linux, sd, "name"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(raw))
		m := csiSensorRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		idx := len(cams)
		cams = append(cams, Camera{
			ID:    itoa(idx),
			Label: m[1] + " (CSI " + itoa(idx) + ")",
			Kind:  "csi",
		})
	}
	return cams
}

// Features derives the spec v2.8 device-feature list from the inventory plus
// fixed-path probes. The returned names are exactly the closed
// compatibility.requiresFeatures enum.
func Features(inv Inventory) []string {
	if runtime.GOOS != "linux" {
		return []string{}
	}
	features := []string{}
	// Trixie ships /usr/bin/chromium, Bookworm /usr/bin/chromium-browser.
	if statAny("/usr/bin/chromium", "/usr/bin/chromium-browser") {
		features = append(features, "desktop-chromium")
	}
	// Fixed paths, not $PATH lookups: the agent's service PATH is minimal
	// and a PATH-based probe would be attacker-influenceable.
	if statAny("/usr/bin/labwc", "/usr/bin/wayfire", "/usr/bin/cage") {
		features = append(features, "wayland-compositor")
	}
	if len(inv.Cameras) > 0 {
		features = append(features, "csi-or-usb-camera")
	}
	return features
}

func statAny(paths ...string) bool {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
