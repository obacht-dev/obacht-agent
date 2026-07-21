package manifest

import "testing"

const managedManifestYAML = `
apiVersion: obacht.dev/v2
kind: Template
metadata: { name: camera-streamer, version: "1.0.0" }
spec:
  minSudoLevel: power
  runtime:
    type: system
    system:
      managed_service:
        binary: mediamtx
`

const kioskManifestYAML = `
apiVersion: obacht.dev/v2
kind: Template
metadata: { name: kiosk-mode, version: "1.0.0" }
spec:
  minSudoLevel: power
  runtime:
    type: system
    system:
      kiosk: {}
`

const hostServiceManifestYAML = `
apiVersion: obacht.dev/v2
kind: Template
metadata: { name: ollama-host, version: "1.0.0" }
spec:
  runtime:
    type: system
    system:
      host_service:
        binary: ollama
`

func TestFlavorDetectors(t *testing.T) {
	cases := []struct {
		name                 string
		yaml                 string
		managed, kiosk, host bool
	}{
		{"managed", managedManifestYAML, true, false, false},
		{"kiosk", kioskManifestYAML, false, true, false},
		{"host_service", hostServiceManifestYAML, false, false, true},
	}
	for _, c := range cases {
		b := []byte(c.yaml)
		if got := HasManagedService(b); got != c.managed {
			t.Errorf("%s: HasManagedService=%v want %v", c.name, got, c.managed)
		}
		if got := HasKiosk(b); got != c.kiosk {
			t.Errorf("%s: HasKiosk=%v want %v", c.name, got, c.kiosk)
		}
		if got := HasHostService(b); got != c.host {
			t.Errorf("%s: HasHostService=%v want %v", c.name, got, c.host)
		}
		if got := RuntimeType(b); got != "system" {
			t.Errorf("%s: RuntimeType=%q want system", c.name, got)
		}
	}
	// A container manifest triggers none of the system flavor detectors.
	container := []byte("spec:\n  runtime:\n    type: container\n    container:\n      image: nginx\n")
	if HasManagedService(container) || HasKiosk(container) || HasHostService(container) {
		t.Error("container manifest matched a system flavor detector")
	}
}
