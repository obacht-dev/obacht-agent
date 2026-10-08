package compat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture points deviceTreeModel and dmiRoot at a temp dir. model is
// written to the device-tree path when non-empty; dmi maps file name to
// contents under the DMI dir.
func fixture(t *testing.T, model string, dmi map[string]string) {
	t.Helper()
	dir := t.TempDir()
	oldModel, oldDMI := deviceTreeModel, dmiRoot
	t.Cleanup(func() { deviceTreeModel, dmiRoot = oldModel, oldDMI })

	deviceTreeModel = filepath.Join(dir, "device-tree", "model")
	dmiRoot = filepath.Join(dir, "dmi")
	if model != "" {
		mustWrite(t, deviceTreeModel, model)
	}
	for name, v := range dmi {
		mustWrite(t, filepath.Join(dmiRoot, name), v)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectHardware(t *testing.T) {
	long := strings.Repeat("x", 200)
	cases := []struct {
		name  string
		model string
		dmi   map[string]string
		want  *Hardware
	}{
		{
			name:  "pi 400",
			model: "Raspberry Pi 400 Rev 1.0\x00",
			want:  &Hardware{Model: "Raspberry Pi 400 Rev 1.0"},
		},
		{
			name:  "pi 5",
			model: "Raspberry Pi 5 Model B Rev 1.0\x00",
			want:  &Hardware{Model: "Raspberry Pi 5 Model B Rev 1.0"},
		},
		{
			name: "dell optiplex 7060",
			dmi: map[string]string{
				"sys_vendor":     "Dell Inc.\n",
				"product_name":   "OptiPlex 7060\n",
				"product_family": "\n",
				"chassis_type":   "35\n",
				"board_vendor":   "Dell Inc.\n",
				"board_name":     "0C96W1\n",
			},
			want: &Hardware{Vendor: "Dell Inc.", Product: "OptiPlex 7060", BoardVendor: "Dell Inc.", BoardName: "0C96W1", Chassis: 35},
		},
		{
			name: "lenovo tiny",
			dmi: map[string]string{
				"sys_vendor":      "LENOVO\n",
				"product_name":    "10T7S0AX00\n",
				"product_version": "ThinkCentre M920q\n",
				"product_family":  "ThinkCentre M920q\n",
				"chassis_type":    "35\n",
			},
			want: &Hardware{Vendor: "LENOVO", Product: "10T7S0AX00", Version: "ThinkCentre M920q", Family: "ThinkCentre M920q", Chassis: 35},
		},
		{
			name: "qemu proxmox",
			dmi: map[string]string{
				"sys_vendor":      "QEMU\n",
				"product_name":    "Standard PC (Q35 + ICH9, 2009)\n",
				"product_version": "pc-q35-8.1\n",
				"chassis_type":    "1\n",
			},
			want: &Hardware{Vendor: "QEMU", Product: "Standard PC (Q35 + ICH9, 2009)", Version: "pc-q35-8.1", Chassis: 1, Virtual: true},
		},
		{
			name: "hyper-v",
			dmi: map[string]string{
				"sys_vendor":   "Microsoft Corporation\n",
				"product_name": "Virtual Machine\n",
			},
			want: &Hardware{Vendor: "Microsoft Corporation", Product: "Virtual Machine", Virtual: true},
		},
		{
			name: "microsoft surface is not virtual",
			dmi: map[string]string{
				"sys_vendor":   "Microsoft Corporation\n",
				"product_name": "Surface Pro 7\n",
			},
			want: &Hardware{Vendor: "Microsoft Corporation", Product: "Surface Pro 7"},
		},
		{
			name: "hetzner cloud",
			dmi: map[string]string{
				"sys_vendor":   "Hetzner\n",
				"product_name": "vServer\n",
			},
			want: &Hardware{Vendor: "Hetzner", Product: "vServer", Virtual: true},
		},
		{
			name: "placeholder bios, nothing left",
			dmi: map[string]string{
				"sys_vendor":      "Default string\n",
				"product_name":    "To Be Filled By O.E.M.\n",
				"product_version": "System Version\n",
				"product_family":  "default STRING\n",
				"board_vendor":    "Not Specified\n",
				"board_name":      "N/A\n",
				"chassis_type":    "garbage\n",
			},
			want: nil,
		},
		{
			name: "placeholder bios with chassis",
			dmi: map[string]string{
				"sys_vendor":   "System manufacturer\n",
				"product_name": "System Product Name\n",
				"chassis_type": "3\n",
			},
			want: &Hardware{Chassis: 3},
		},
		{
			name: "long string capped",
			dmi:  map[string]string{"product_name": long},
			want: &Hardware{Product: long[:64]},
		},
		{
			name: "control characters removed",
			dmi:  map[string]string{"sys_vendor": "  Ac\x00me\x1b[31m\tCorp\x7f \n", "product_name": "Box​ 1"},
			want: &Hardware{Vendor: "Acme[31m Corp", Product: "Box 1"},
		},
		{
			name: "nothing at all",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture(t, tc.model, tc.dmi)
			got := detectHardware()
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("got  %+v\nwant %+v", *got, *tc.want)
			}
		})
	}
}

// detectDevice drives template gating; hardware.model must not change it.
func TestDetectDeviceUnchanged(t *testing.T) {
	cases := map[string]string{
		"Raspberry Pi 400 Rev 1.0\x00":       "raspberry-pi-4",
		"Raspberry Pi 4 Model B Rev 1.5\x00": "raspberry-pi-4",
		"Raspberry Pi 5 Model B Rev 1.0\x00": "raspberry-pi-5",
	}
	for model, want := range cases {
		fixture(t, model, nil)
		if got := detectDevice(); got != want {
			t.Errorf("detectDevice(%q) = %q, want %q", model, got, want)
		}
	}
}

// Data minimisation: serials, UUIDs and asset tags present on disk must
// never reach the register payload.
func TestSerialsNeverReported(t *testing.T) {
	secrets := map[string]string{
		"product_serial":    "SERIAL-PRODUCT-123",
		"product_uuid":      "4c4c4544-0042-3510-8051-b4c04f4e5a32",
		"board_serial":      "SERIAL-BOARD-456",
		"chassis_serial":    "SERIAL-CHASSIS-789",
		"board_asset_tag":   "ASSET-BOARD-1",
		"chassis_asset_tag": "ASSET-CHASSIS-2",
	}
	dmi := map[string]string{
		"sys_vendor":   "Dell Inc.\n",
		"product_name": "OptiPlex 7060\n",
		"chassis_type": "35\n",
	}
	for k, v := range secrets {
		dmi[k] = v + "\n"
	}
	fixture(t, "Raspberry Pi 5 Model B Rev 1.0\x00", dmi)
	mustWrite(t, filepath.Join(filepath.Dir(deviceTreeModel), "serial-number"), "SERIAL-DT-10000000abcdef\x00")

	b, err := json.Marshal(Detect(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, `"product":"OptiPlex 7060"`) {
		t.Fatalf("fixture not read: %s", out)
	}
	for _, v := range append(mapValues(secrets), "SERIAL-DT-10000000abcdef") {
		if strings.Contains(out, v) {
			t.Errorf("payload leaks %q: %s", v, out)
		}
	}
	for _, name := range dmiFiles {
		if _, bad := secrets[name]; bad {
			t.Errorf("dmiFiles includes forbidden %q", name)
		}
	}
}

func TestHardwareOmittedWhenEmpty(t *testing.T) {
	fixture(t, "", nil)
	b, err := json.Marshal(Detect(""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hardware") {
		t.Fatalf("empty hardware should be omitted: %s", b)
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
