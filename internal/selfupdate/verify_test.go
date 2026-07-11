package selfupdate

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"aead.dev/minisign"
	"github.com/obacht-dev/obacht-agent/internal/trust"
)

// buildBundleFromKey mirrors what VerifyFile does internally, but over an
// explicit key set so the test doesn't depend on the (empty) embedded set.
func verifyWith(t *testing.T, pub minisign.PublicKey, content, sig []byte) error {
	t.Helper()
	text, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.New([]trust.KeyEntry{{Label: "test", PubKey: string(text)}})
	if err != nil {
		t.Fatal(err)
	}
	return b.Verify(content, sig)
}

func TestVerifyFileNoKeysIsDistinctFromRejection(t *testing.T) {
	// The embedded set ships empty; VerifyFile must return ErrNoKeys (a
	// migration-phase "cannot verify"), NEVER nil and NEVER a plain
	// rejection — the installer keys its skip-vs-abort decision on this.
	err := VerifyFile([]byte("x"), []byte("y"))
	if !errors.Is(err, ErrNoKeys) {
		t.Fatalf("empty embedded keys: got %v, want ErrNoKeys", err)
	}
}

func TestReleaseVerifyRoundtrip(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("obacht-agent_v9.9.9_linux_arm64.tar.gz bytes")
	sig := minisign.Sign(priv, content)

	if err := verifyWith(t, pub, content, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Tampered content must be rejected.
	if err := verifyWith(t, pub, append(content, '!'), sig); err == nil {
		t.Fatal("tampered content accepted")
	}
	// A signature from a different key must be rejected.
	otherPub, _, _ := minisign.GenerateKey(rand.Reader)
	if err := verifyWith(t, otherPub, content, sig); err == nil {
		t.Fatal("signature verified under the wrong key")
	}
}

func TestLoadReleaseKeysReadsDropInDir(t *testing.T) {
	// LoadFromDir(ReleaseTrustDir) tolerates a missing dir; a present dir
	// with a .pub is picked up. We exercise the trust.LoadFromDir path a
	// LoadReleaseKeys would use (ReleaseTrustDir itself is a fixed system
	// path, so we test the underlying loader with a temp dir).
	dir := t.TempDir()
	pub, _, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := pub.MarshalText()
	if err := os.WriteFile(filepath.Join(dir, "op-key.pub"), text, 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := trust.LoadFromDir(dir)
	if err != nil || len(keys) != 1 {
		t.Fatalf("LoadFromDir: keys=%d err=%v", len(keys), err)
	}
	if _, err := trust.New(keys); err != nil {
		t.Fatalf("bundle from drop-in key: %v", err)
	}
}
