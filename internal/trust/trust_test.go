package trust

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"aead.dev/minisign"
)

// helper: generate a fresh keypair + sign content with it.
func sign(t *testing.T, content []byte) (pubText string, sig []byte) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sig = minisign.Sign(priv, content)
	pubBytes, err := pub.MarshalText()
	if err != nil {
		t.Fatalf("pub.MarshalText: %v", err)
	}
	return string(pubBytes), sig
}

func TestBundleVerifyOK(t *testing.T) {
	content := []byte("kind: container\nimage: caddy:2-alpine\n")
	pub, sig := sign(t, content)
	b, err := New([]KeyEntry{{Label: "test", PubKey: pub}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Verify(content, sig); err != nil {
		t.Fatalf("Verify should succeed: %v", err)
	}
}

func TestBundleVerifyTamperedContent(t *testing.T) {
	content := []byte("kind: container\nimage: caddy:2-alpine\n")
	pub, sig := sign(t, content)
	b, err := New([]KeyEntry{{Label: "test", PubKey: pub}})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte("kind: container\nimage: evil/cryptominer:latest\n")
	if err := b.Verify(tampered, sig); err == nil {
		t.Fatal("tampered content must fail verification")
	}
}

func TestBundleVerifyWrongKey(t *testing.T) {
	content := []byte("hello")
	_, sig := sign(t, content) // signed by key A
	pubB, _ := sign(t, content) // generate key B independently
	b, err := New([]KeyEntry{{Label: "B-only", PubKey: pubB}})
	if err != nil {
		t.Fatal(err)
	}
	// sig was made by key A, bundle only knows key B → must fail.
	if err := b.Verify(content, sig); err == nil {
		t.Fatal("signature from untrusted key must fail")
	}
}

func TestBundleVerifyMultiKeyAcceptsAny(t *testing.T) {
	content := []byte("hello")
	pubA, _ := sign(t, content)
	pubB, sigB := sign(t, content)
	b, err := New([]KeyEntry{
		{Label: "A", PubKey: pubA},
		{Label: "B", PubKey: pubB},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(content, sigB); err != nil {
		t.Fatalf("any-key match must succeed: %v", err)
	}
}

func TestNewRejectsEmpty(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("empty bundle must be rejected (fail-closed)")
	}
}

func TestLoadFromDir(t *testing.T) {
	dir := t.TempDir()
	pub, _ := sign(t, []byte("x"))
	if err := os.WriteFile(filepath.Join(dir, "site.pub"), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	// Non-pub file is ignored.
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Label != "site.pub" {
		t.Fatalf("label mismatch: %q", entries[0].Label)
	}
}

func TestLoadFromDirMissingIsEmpty(t *testing.T) {
	entries, err := LoadFromDir("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty, got %d", len(entries))
	}
}
