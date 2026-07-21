package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Mirror of a real Pi 4 + HQ camera (imx477) sysfs tree: one sensor subdev
// among 17 codec/ISP nodes — only the sensor may surface as a camera.
func TestDetectCSICameras_FiltersCodecNodes(t *testing.T) {
	if runtime.GOOS != "linux" {
		// detectCSICameras reads the fake tree fine on any OS; only Collect()
		// gates on GOOS. Test the detector directly.
	}
	dir := t.TempDir()
	nodes := map[string]string{
		"v4l-subdev0": "imx477 10-001a",
		"video0":      "unicam-image",
		"video1":      "unicam-embedded",
		"video10":     "bcm2835-codec-decode",
		"video11":     "bcm2835-codec-encode",
		"video13":     "bcm2835-isp-output0",
		"video19":     "rpi-hevc-dec",
	}
	for node, name := range nodes {
		if err := os.MkdirAll(filepath.Join(dir, node), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, node, "name"), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := sysfsVideo4linux
	sysfsVideo4linux = dir
	defer func() { sysfsVideo4linux = orig }()

	cams := detectCSICameras()
	if len(cams) != 1 {
		t.Fatalf("expected exactly 1 camera, got %+v", cams)
	}
	if cams[0].ID != "0" || cams[0].Kind != "csi" {
		t.Errorf("unexpected camera %+v", cams[0])
	}
	if cams[0].Label != "imx477 (CSI 0)" {
		t.Errorf("unexpected label %q", cams[0].Label)
	}
}

func TestDetectCSICameras_TwoSensors(t *testing.T) {
	dir := t.TempDir()
	for node, name := range map[string]string{
		"v4l-subdev0": "imx708 4-001a",
		"v4l-subdev1": "ov5647 10-0036",
		"video0":      "unicam-image",
	} {
		os.MkdirAll(filepath.Join(dir, node), 0o755)
		os.WriteFile(filepath.Join(dir, node, "name"), []byte(name), 0o644)
	}
	orig := sysfsVideo4linux
	sysfsVideo4linux = dir
	defer func() { sysfsVideo4linux = orig }()

	cams := detectCSICameras()
	if len(cams) != 2 {
		t.Fatalf("expected 2 cameras, got %+v", cams)
	}
	if cams[0].ID != "0" || cams[1].ID != "1" {
		t.Errorf("indices not sequential: %+v", cams)
	}
}

func TestDetectCSICameras_MissingSysfs(t *testing.T) {
	orig := sysfsVideo4linux
	sysfsVideo4linux = "/nonexistent/for/test"
	defer func() { sysfsVideo4linux = orig }()
	if cams := detectCSICameras(); cams != nil {
		t.Errorf("expected nil, got %+v", cams)
	}
}
