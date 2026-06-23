package diskcheck

import (
	"os"
	"strconv"
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
