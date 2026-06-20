//go:build darwin

package telemetry

import "testing"

// Smoke test for the macOS collector: it must report real disk + total RAM.
// On native (cgo) builds it also reports CPU% and used RAM.
func TestDarwinCollectSmoke(t *testing.T) {
	s, err := NewCollector().Collect()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if s.RAMTotal == nil || *s.RAMTotal == 0 {
		t.Error("expected non-zero RAMTotal")
	}
	if s.DiskTotal == nil || *s.DiskTotal == 0 {
		t.Error("expected non-zero DiskTotal")
	}
	cpu := "<nil>"
	if s.CPUUsage != nil {
		cpu = "set"
	}
	ramUsed := "<nil>"
	if s.RAMUsed != nil {
		ramUsed = "set"
	}
	var ramT, ramU, diskU uint64
	if s.RAMTotal != nil {
		ramT = *s.RAMTotal
	}
	if s.RAMUsed != nil {
		ramU = *s.RAMUsed
	}
	if s.DiskUsed != nil {
		diskU = *s.DiskUsed
	}
	var cpuV float64
	if s.CPUUsage != nil {
		cpuV = *s.CPUUsage
	}
	t.Logf("darwin telemetry: cpu=%s(%.1f%%) ramUsed=%s(%d) ramTotal=%d disk=%d",
		cpu, cpuV, ramUsed, ramU, ramT, diskU)
}
