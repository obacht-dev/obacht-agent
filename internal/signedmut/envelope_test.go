package signedmut

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// memReplay is an in-memory ReplayStore for tests.
type memReplay map[string]bool

func (m memReplay) CheckAndMarkNonce(_ context.Context, nonce string, _ time.Time) (bool, error) {
	if m[nonce] {
		return false, nil
	}
	m[nonce] = true
	return true, nil
}

const testDeviceID = "6f1c2a3b-0000-4111-8222-333344445555"

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// signEnvelope builds a wire envelope the way the webapp does: canonicalize
// the mutation, sign the canonical bytes, base64 everything.
func signEnvelope(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, mutation map[string]any) []byte {
	t.Helper()
	mutJSON, err := json.Marshal(mutation)
	if err != nil {
		t.Fatalf("marshal mutation: %v", err)
	}
	tree, err := decodeJSON(mutJSON)
	if err != nil {
		t.Fatalf("decode mutation: %v", err)
	}
	canon, err := canonicalize(tree)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	env := map[string]any{
		"mutation":          json.RawMessage(mutJSON),
		"sig_b64":           base64.StdEncoding.EncodeToString(sig),
		"signer_pubkey_b64": base64.StdEncoding.EncodeToString(pub),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

func validMutation(now time.Time) map[string]any {
	return map[string]any{
		"v":         1,
		"device_id": testDeviceID,
		"op":        "domain.upsert",
		"params":    map[string]any{"domain": "blog.example.com", "desired_status": "bound"},
		"nonce":     fmt.Sprintf("nonce-%d", now.UnixNano()),
		"iat":       now.Unix(),
		"exp":       now.Add(120 * time.Second).Unix(),
		"key_id":    "k-123",
	}
}

func TestVerifyAccepts(t *testing.T) {
	pub, priv := testKeypair(t)
	v := NewVerifier([]UserKey{{Label: "k-123.pub", Pub: pub}})
	now := time.Now()
	raw := signEnvelope(t, priv, pub, validMutation(now))

	m, key, err := v.Verify(context.Background(), raw, testDeviceID, now, memReplay{})
	if err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if m.Op != "domain.upsert" || key.Label != "k-123.pub" {
		t.Errorf("unexpected result op=%s key=%s", m.Op, key.Label)
	}
	var p struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil || p.Domain != "blog.example.com" {
		t.Errorf("params not preserved: %v %+v", err, p)
	}
}

func denyReason(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected deny, got accept")
	}
	var de *DenyError
	if !errAs(err, &de) {
		t.Fatalf("expected DenyError, got %T: %v", err, err)
	}
	return de.Reason
}

func errAs(err error, target **DenyError) bool {
	for err != nil {
		if de, ok := err.(*DenyError); ok {
			*target = de
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestVerifyDenyMatrix(t *testing.T) {
	pub, priv := testKeypair(t)
	otherPub, otherPriv := testKeypair(t)
	v := NewVerifier([]UserKey{{Label: "k.pub", Pub: pub}})
	now := time.Now()

	t.Run("untrusted key", func(t *testing.T) {
		raw := signEnvelope(t, otherPriv, otherPub, validMutation(now))
		_, _, err := v.Verify(context.Background(), raw, testDeviceID, now, memReplay{})
		if got := denyReason(t, err); got != DenyUntrustedKey {
			t.Errorf("reason = %s, want %s", got, DenyUntrustedKey)
		}
	})

	t.Run("tampered params", func(t *testing.T) {
		raw := signEnvelope(t, priv, pub, validMutation(now))
		tampered := []byte(strings.Replace(string(raw), "blog.example.com", "evil.example.com", 1))
		_, _, err := v.Verify(context.Background(), tampered, testDeviceID, now, memReplay{})
		if got := denyReason(t, err); got != DenySig {
			t.Errorf("reason = %s, want %s", got, DenySig)
		}
	})

	t.Run("wrong device", func(t *testing.T) {
		raw := signEnvelope(t, priv, pub, validMutation(now))
		_, _, err := v.Verify(context.Background(), raw, "another-device", now, memReplay{})
		if got := denyReason(t, err); got != DenyDeviceMismatch {
			t.Errorf("reason = %s, want %s", got, DenyDeviceMismatch)
		}
	})

	t.Run("expired", func(t *testing.T) {
		m := validMutation(now)
		m["iat"] = now.Add(-10 * time.Minute).Unix()
		m["exp"] = now.Add(-8 * time.Minute).Unix()
		raw := signEnvelope(t, priv, pub, m)
		_, _, err := v.Verify(context.Background(), raw, testDeviceID, now, memReplay{})
		if got := denyReason(t, err); got != DenyExpired {
			t.Errorf("reason = %s, want %s", got, DenyExpired)
		}
	})

	t.Run("future iat", func(t *testing.T) {
		m := validMutation(now)
		m["iat"] = now.Add(5 * time.Minute).Unix()
		m["exp"] = now.Add(7 * time.Minute).Unix()
		raw := signEnvelope(t, priv, pub, m)
		_, _, err := v.Verify(context.Background(), raw, testDeviceID, now, memReplay{})
		if got := denyReason(t, err); got != DenyFutureIat {
			t.Errorf("reason = %s, want %s", got, DenyFutureIat)
		}
	})

	t.Run("window too long", func(t *testing.T) {
		m := validMutation(now)
		m["exp"] = now.Add(2 * time.Hour).Unix()
		raw := signEnvelope(t, priv, pub, m)
		_, _, err := v.Verify(context.Background(), raw, testDeviceID, now, memReplay{})
		if got := denyReason(t, err); got != DenyWindow {
			t.Errorf("reason = %s, want %s", got, DenyWindow)
		}
	})

	t.Run("replay", func(t *testing.T) {
		replay := memReplay{}
		raw := signEnvelope(t, priv, pub, validMutation(now))
		if _, _, err := v.Verify(context.Background(), raw, testDeviceID, now, replay); err != nil {
			t.Fatalf("first verify should pass: %v", err)
		}
		_, _, err := v.Verify(context.Background(), raw, testDeviceID, now, replay)
		if got := denyReason(t, err); got != DenyReplay {
			t.Errorf("reason = %s, want %s", got, DenyReplay)
		}
	})

	t.Run("failed verify does not burn nonce", func(t *testing.T) {
		replay := memReplay{}
		m := validMutation(now)
		raw := signEnvelope(t, priv, pub, m)
		tampered := []byte(strings.Replace(string(raw), "blog.example.com", "evil.example.com", 1))
		if _, _, err := v.Verify(context.Background(), tampered, testDeviceID, now, replay); err == nil {
			t.Fatal("tampered must fail")
		}
		// The original (untampered) envelope must still be accepted.
		if _, _, err := v.Verify(context.Background(), raw, testDeviceID, now, replay); err != nil {
			t.Errorf("nonce was burned by a failed attempt: %v", err)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		_, _, err := v.Verify(context.Background(), []byte("{nope"), testDeviceID, now, memReplay{})
		if got := denyReason(t, err); got != DenyMalformed {
			t.Errorf("reason = %s, want %s", got, DenyMalformed)
		}
	})
}

func TestParseOpenSSHEd25519RoundTrip(t *testing.T) {
	pub, _ := testKeypair(t)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(marshalSSHEd25519(pub)) + " user@obacht"
	parsed, err := ParseOpenSSHEd25519(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Equal(pub) {
		t.Error("round-trip key mismatch")
	}
	if _, err := ParseOpenSSHEd25519("ssh-rsa AAAA user@x"); err == nil {
		t.Error("rsa key must be rejected")
	}
	fp := UserKey{Pub: pub}.Fingerprint()
	if !strings.HasPrefix(fp, "SHA256:") || strings.HasSuffix(fp, "=") {
		t.Errorf("fingerprint format unexpected: %s", fp)
	}
}
