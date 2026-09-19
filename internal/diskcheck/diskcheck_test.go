package diskcheck

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestMinFreeBytes(t *testing.T) {
	t.Setenv(MinFreeBytesEnv, "")
	if got := MinFreeBytes(); got != DefaultMinFreeBytes {
		t.Fatalf("default = %d, want %d", got, DefaultMinFreeBytes)
	}
	t.Setenv(MinFreeBytesEnv, "12345")
	if got := MinFreeBytes(); got != 12345 {
		t.Fatalf("override = %d, want 12345", got)
	}
	// Garbage / zero falls back to the default.
	t.Setenv(MinFreeBytesEnv, "nope")
	if got := MinFreeBytes(); got != DefaultMinFreeBytes {
		t.Fatalf("garbage override = %d, want default", got)
	}
}

func TestFreeBytes(t *testing.T) {
	free, ok := FreeBytes(t.TempDir())
	if !ok || free == 0 {
		t.Fatalf("FreeBytes(tmp) = (%d, %v), want (>0, true)", free, ok)
	}
	if _, ok := FreeBytes("/definitely/not/a/real/path/obacht"); ok {
		t.Fatal("FreeBytes(missing) ok = true, want false")
	}
}

func TestEnsureFree(t *testing.T) {
	dir := t.TempDir()

	// Fails open when the path can't be queried.
	if err := EnsureFree("/definitely/not/a/real/path/obacht"); err != nil {
		t.Fatalf("EnsureFree(missing) = %v, want nil (fail open)", err)
	}

	// A tiny floor passes on any real filesystem.
	t.Setenv(MinFreeBytesEnv, "1")
	if err := EnsureFree(dir); err != nil {
		t.Fatalf("EnsureFree with 1-byte floor = %v, want nil", err)
	}

	// An absurd floor (16 EiB - 1) is below no real filesystem → error.
	t.Setenv(MinFreeBytesEnv, strconv.FormatUint(^uint64(0), 10))
	if err := EnsureFree(dir); err == nil {
		t.Fatal("EnsureFree with max floor = nil, want error")
	}
}

func TestEnsureFreeEnvUnset(t *testing.T) {
	// Belt and braces: default path doesn't panic and treats an empty env as
	// "use default".
	_ = os.Unsetenv(MinFreeBytesEnv)
	if err := EnsureFree(t.TempDir()); err != nil {
		t.Fatalf("EnsureFree default floor on tmp = %v, want nil", err)
	}
}

func TestEnsureFreeAtLeast(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(MinFreeBytesEnv, "1")

	// Fails open when the path can't be queried, even with a huge requirement.
	if err := EnsureFreeAtLeast("/definitely/not/a/real/path/obacht", ^uint64(0)); err != nil {
		t.Fatalf("EnsureFreeAtLeast(missing) = %v, want nil (fail open)", err)
	}

	// A tiny template requirement passes on any real filesystem; 0 means
	// "floor only" and must behave exactly like EnsureFree.
	if err := EnsureFreeAtLeast(dir, 1); err != nil {
		t.Fatalf("EnsureFreeAtLeast(1 byte) = %v, want nil", err)
	}
	if err := EnsureFreeAtLeast(dir, 0); err != nil {
		t.Fatalf("EnsureFreeAtLeast(0) = %v, want nil", err)
	}

	// A huge template requirement (40 TiB) fails and the message must name
	// both amounts and say the requirement came from the template.
	err := EnsureFreeAtLeast(dir, 40<<40)
	if err == nil {
		t.Fatal("EnsureFreeAtLeast(40 TiB) = nil, want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "template requires 40.0 TiB free") {
		t.Errorf("error should name the template requirement: %q", msg)
	}
	if !strings.Contains(msg, "free,") || !strings.Contains(msg, "iB free") {
		t.Errorf("error should name the available amount: %q", msg)
	}

	// When the agent floor is the binding requirement the message stays the
	// EnsureFree wording (the template asked for less than the floor).
	t.Setenv(MinFreeBytesEnv, strconv.FormatUint(^uint64(0), 10))
	err = EnsureFreeAtLeast(dir, 1)
	if err == nil || !strings.Contains(err.Error(), "need at least") || strings.Contains(err.Error(), "template requires") {
		t.Errorf("floor-bound error wording wrong: %v", err)
	}
}

func TestMiB(t *testing.T) {
	if got := MiB(0); got != 0 {
		t.Errorf("MiB(0) = %d", got)
	}
	if got := MiB(-5); got != 0 {
		t.Errorf("MiB(-5) = %d, want 0 (no wrap-around)", got)
	}
	if got := MiB(40960); got != 40960<<20 {
		t.Errorf("MiB(40960) = %d", got)
	}
}
