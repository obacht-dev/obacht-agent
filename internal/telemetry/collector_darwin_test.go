//go:build darwin

package telemetry

import "testing"

// Smoke test for the macOS collector: it must report real disk + total RAM.
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
	var ramT, diskU, diskT uint64
	if s.RAMTotal != nil {
		ramT = *s.RAMTotal
	}
	if s.DiskUsed != nil {
		diskU = *s.DiskUsed
	}
	if s.DiskTotal != nil {
		diskT = *s.DiskTotal
	}
	local := "<nil>"
	if s.LocalIP != nil {
		local = *s.LocalIP
	}
	t.Logf("darwin telemetry: ramTotal=%d disk=%d/%d localIP=%s", ramT, diskU, diskT, local)
}
