package enckey

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type memStore struct{ m map[string]string }

func (s *memStore) GetMeta(_ context.Context, key string) (string, error) {
	v, ok := s.m[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (s *memStore) SetMeta(_ context.Context, key, value string) error {
	s.m[key] = value
	return nil
}

func TestEnsurePublicKeyIdempotent(t *testing.T) {
	s := &memStore{m: map[string]string{}}
	ctx := context.Background()

	pub1, err := EnsurePublicKey(ctx, s)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(pub1)
	if err != nil || len(raw) != 32 {
		t.Fatalf("pubkey not base64 of 32 bytes: %q (%v)", pub1, err)
	}

	pub2, err := EnsurePublicKey(ctx, s)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if pub1 != pub2 {
		t.Fatalf("keypair not stable: %q vs %q", pub1, pub2)
	}
}

func TestEnsurePublicKeyRegeneratesOnCorruptKey(t *testing.T) {
	s := &memStore{m: map[string]string{metaPrivKey: "definitely-not-base64!"}}
	pub, err := EnsurePublicKey(context.Background(), s)
	if err != nil || pub == "" {
		t.Fatalf("corrupt key should regenerate, got %q, %v", pub, err)
	}
}

func TestFingerprint(t *testing.T) {
	s := &memStore{m: map[string]string{}}
	pub, err := EnsurePublicKey(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp, "SHA256:") || strings.HasSuffix(fp, "=") {
		t.Fatalf("fingerprint shape wrong: %q", fp)
	}
	if _, err := Fingerprint("not-base64!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
