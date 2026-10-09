package sync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/signedmut"
)

// signRequest builds a wire envelope for op/params. json.Marshal of a map
// sorts keys and writes compact output, which is the JCS form for the ASCII
// test values used here.
func signRequest(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, device, op string, params map[string]any, nonce string) json.RawMessage {
	t.Helper()
	now := time.Now().Unix()
	m := map[string]any{
		"v": 1, "device_id": device, "op": op, "params": params,
		"nonce": nonce, "iat": now, "exp": now + 120, "key_id": "k1",
	}
	canon, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]any{
		"mutation":          json.RawMessage(canon),
		"sig_b64":           base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon)),
		"signer_pubkey_b64": base64.StdEncoding.EncodeToString(pub),
	}
	raw, _ := json.Marshal(env)
	return raw
}

func pinnedSyncer(t *testing.T) (*Syncer, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s, _, _ := newDispatchSyncer(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.SetSignedMutations(signedmut.NewVerifier([]signedmut.UserKey{{Label: "test", Pub: pub}}), nil)
	return s, pub, priv
}

func TestAuthorizeRequestAcceptsMatchingSignature(t *testing.T) {
	s, pub, priv := pinnedSyncer(t)
	params := map[string]any{"instance_id": "i1", "service": "", "tail": int64(200)}
	env := signRequest(t, priv, pub, "dev-1", "logs.read", params, "n-ok")
	if err := s.AuthorizeRequest(context.Background(), env, "logs.read", params); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	// Same envelope again is a replay.
	if err := s.AuthorizeRequest(context.Background(), env, "logs.read", params); err == nil {
		t.Fatal("replayed envelope must be rejected")
	}
}

func TestAuthorizeRequestRejects(t *testing.T) {
	s, pub, priv := pinnedSyncer(t)
	ctx := context.Background()
	params := map[string]any{"instance_id": "i1", "path": "index.html"}

	if err := s.AuthorizeRequest(ctx, nil, "files.delete", params); err != ErrSignatureRequired {
		t.Errorf("unsigned: want ErrSignatureRequired, got %v", err)
	}
	// Signed for list, used for delete.
	env := signRequest(t, priv, pub, "dev-1", "files.list", params, "n-op")
	if err := s.AuthorizeRequest(ctx, env, "files.delete", params); err == nil || !strings.Contains(err.Error(), "op") {
		t.Errorf("op mismatch must be rejected, got %v", err)
	}
	// Signed for one path, relayed with another.
	env = signRequest(t, priv, pub, "dev-1", "files.delete", params, "n-path")
	other := map[string]any{"instance_id": "i1", "path": "secret.db"}
	if err := s.AuthorizeRequest(ctx, env, "files.delete", other); err == nil {
		t.Error("params mismatch must be rejected")
	}
	// Signed for another device.
	env = signRequest(t, priv, pub, "dev-2", "files.delete", params, "n-dev")
	if err := s.AuthorizeRequest(ctx, env, "files.delete", params); err == nil {
		t.Error("device mismatch must be rejected")
	}
	// Signed by a key that is not pinned.
	opub, opriv, _ := ed25519.GenerateKey(rand.Reader)
	env = signRequest(t, opriv, opub, "dev-1", "files.delete", params, "n-key")
	if err := s.AuthorizeRequest(ctx, env, "files.delete", params); err == nil {
		t.Error("untrusted key must be rejected")
	}
	// Upload: the hash binds the content.
	sum := sha256.Sum256([]byte("hello"))
	up := map[string]any{"instance_id": "i1", "path": "a.txt", "content_sha256": hex.EncodeToString(sum[:])}
	env = signRequest(t, priv, pub, "dev-1", "files.upload", up, "n-up")
	evil := sha256.Sum256([]byte("evil"))
	swapped := map[string]any{"instance_id": "i1", "path": "a.txt", "content_sha256": hex.EncodeToString(evil[:])}
	if err := s.AuthorizeRequest(ctx, env, "files.upload", swapped); err == nil {
		t.Error("swapped upload content must be rejected")
	}
}

func TestAuthorizeRequestWithoutPinnedKeys(t *testing.T) {
	s, _, _ := newDispatchSyncer(t)
	if err := s.AuthorizeRequest(context.Background(), json.RawMessage(`{}`), "logs.read", map[string]any{}); err == nil {
		t.Fatal("a device without pinned keys must refuse")
	}
}
