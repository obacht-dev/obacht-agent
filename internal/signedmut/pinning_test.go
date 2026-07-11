package signedmut

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func genPubLine(t *testing.T, comment string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := marshalSSHEd25519(pub)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire)
	if comment != "" {
		line += " " + comment
	}
	return line, pub
}

func TestPinUserKeyRoundtrip(t *testing.T) {
	dir := t.TempDir() + "/user-keys.d" // must be created by PinUserKey
	line, pub := genPubLine(t, "webapp@test")

	key, created, err := PinUserKey(dir, line)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on first pin")
	}
	if string(key.Pub) != string(pub) {
		t.Fatal("pinned key does not match input")
	}

	// Idempotent second pin.
	key2, created2, err := PinUserKey(dir, line)
	if err != nil {
		t.Fatalf("re-pin: %v", err)
	}
	if created2 {
		t.Fatal("expected created=false on duplicate pin")
	}
	if key2.Label != key.Label {
		t.Fatalf("duplicate pin changed label: %q != %q", key2.Label, key.Label)
	}

	// Loader sees exactly one key; file perms are 0600.
	keys, problems := LoadUserKeys(dir)
	if len(problems) != 0 || len(keys) != 1 {
		t.Fatalf("load: keys=%d problems=%v", len(keys), problems)
	}
	fi, err := os.Stat(filepath.Join(dir, key.Label))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("pin file mode = %v, want 0600", fi.Mode().Perm())
	}

	// Unpin by fingerprint empties the store.
	removed, err := UnpinUserKey(dir, key.Fingerprint())
	if err != nil || removed != 1 {
		t.Fatalf("unpin: removed=%d err=%v", removed, err)
	}
	keys, _ = LoadUserKeys(dir)
	if len(keys) != 0 {
		t.Fatalf("expected empty store after unpin, got %d", len(keys))
	}
}

func TestPinUserKeyRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{
		"",
		"ssh-rsa AAAAB3NzaC1yc2E comment",
		"ssh-ed25519 not-base64 x",
		"restrict,command=\"/bin/true\" ssh-ed25519 AAAA x", // option-prefixed
		"ssh-ed25519 AAAA\nssh-ed25519 BBBB",                // multi-line
		strings.Repeat("a", 2048),
	} {
		if _, _, err := PinUserKey(dir, bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	if keys, _ := LoadUserKeys(dir); len(keys) != 0 {
		t.Fatal("garbage input must not create pins")
	}
}

func TestImportAuthorizedKeys(t *testing.T) {
	dir := t.TempDir() + "/user-keys.d"
	auth := filepath.Join(t.TempDir(), "authorized_keys")

	good1, _ := genPubLine(t, "install@pi")
	good2, _ := genPubLine(t, "")
	content := strings.Join([]string{
		"# managed by obacht",
		"",
		good1,
		"ssh-rsa AAAAB3NzaC1yc2EAAA legacy@laptop", // skipped: rsa
		"restrict,pty " + good2,                    // skipped: options prefix
		"ssh-ed25519 %%%broken%%% x",               // skipped: bad base64
		good2,                                      // imported
		good1,                                      // duplicate: no new pin
	}, "\n") + "\n"
	if err := os.WriteFile(auth, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pinned, skipped, err := ImportAuthorizedKeys(dir, auth)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(pinned) != 2 {
		t.Fatalf("pinned=%d, want 2", len(pinned))
	}
	if skipped != 3 {
		t.Fatalf("skipped=%d, want 3", skipped)
	}
	keys, _ := LoadUserKeys(dir)
	if len(keys) != 2 {
		t.Fatalf("store holds %d keys, want 2", len(keys))
	}

	// Missing file surfaces os.ErrNotExist so the caller can retry later.
	if _, _, err := ImportAuthorizedKeys(dir, auth+".missing"); !os.IsNotExist(err) {
		t.Fatalf("expected ErrNotExist, got %v", err)
	}
}

func TestVerifierFingerprints(t *testing.T) {
	dir := t.TempDir()
	line, _ := genPubLine(t, "fp@test")
	key, _, err := PinUserKey(dir, line)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := LoadUserKeys(dir)
	v := NewVerifier(keys)
	fps := v.Fingerprints()
	if len(fps) != 1 || fps[0] != key.Fingerprint() {
		t.Fatalf("fingerprints = %v, want [%s]", fps, key.Fingerprint())
	}
	if !strings.HasPrefix(fps[0], "SHA256:") {
		t.Fatalf("fingerprint %q is not OpenSSH SHA256 format", fps[0])
	}
}
