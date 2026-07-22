package basicauth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestValidateCredentials(t *testing.T) {
	ok := func(u, p string) {
		t.Helper()
		if err := ValidateCredentials(u, p); err != nil {
			t.Errorf("expected valid (%q, %q): %v", u, p, err)
		}
	}
	bad := func(u, p string) {
		t.Helper()
		if err := ValidateCredentials(u, p); err == nil {
			t.Errorf("expected invalid (%q, %q)", u, p)
		}
	}
	ok("admin", "supersecret")
	ok("robert.s_test@x-1", "pässwörter-sind-ok")
	bad("", "supersecret")
	bad("has space", "supersecret")
	bad("brace{", "supersecret")
	bad("admin", "short")
	bad("admin", "with\nnewline1")
	bad("admin", strings.Repeat("x", 73))
	bad(strings.Repeat("u", 65), "supersecret")
}

func TestHashRoundtripAndShape(t *testing.T) {
	h, err := Hash("supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidHash(h) {
		t.Errorf("generated hash rejected by ValidHash: %s", h)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("supersecret")); err != nil {
		t.Errorf("hash does not verify: %v", err)
	}
}

func TestValidHashRejectsGarbage(t *testing.T) {
	for _, h := range []string{"", "plaintext", "$2a$10$short", "$1$md5$whatever", "$2a$10$" + strings.Repeat("{", 53)} {
		if ValidHash(h) {
			t.Errorf("ValidHash accepted %q", h)
		}
	}
}
