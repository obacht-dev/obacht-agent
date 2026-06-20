package sync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/obacht-dev/obacht-agent/internal/api"
	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/signedmut"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// signWithTestTrust generates a minisign keypair, drops the pubkey into a
// temp trust dir, points OBACHT_TRUST_DIR at it, and returns the manifest
// bytes + signature so manifest.Verify (embedded keys + trust.d) accepts
// it. Lets us exercise the post-verify gating + materialise path without
// the prod registry private key.
func signWithTestTrust(t *testing.T, manifestBytes []byte) (b64Manifest, b64Sig string) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sig := minisign.Sign(priv, manifestBytes)
	pubText, err := pub.MarshalText()
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.pub"), pubText, 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	t.Setenv("OBACHT_TRUST_DIR", dir)
	return base64.StdEncoding.EncodeToString(manifestBytes),
		base64.StdEncoding.EncodeToString(sig)
}

func newDispatchSyncer(t *testing.T) (*Syncer, *store.Store, *triggerSpy) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	w, err := audit.New(st, filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	client := api.New("", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	spy := &triggerSpy{}
	s := New(client, st, spy, "dev-1", "test", slog.New(slog.NewTextHandler(io.Discard, nil)), w)
	return s, st, spy
}

func mutation(t *testing.T, op string, params map[string]any) *signedmut.Mutation {
	t.Helper()
	raw, _ := json.Marshal(params)
	return &signedmut.Mutation{V: 1, DeviceID: "dev-1", Op: op, Params: raw, Nonce: "n"}
}

func TestDispatchInstanceUpsertContainer(t *testing.T) {
	s, st, spy := newDispatchSyncer(t)
	manifestBytes := []byte(containerTestManifest)
	mb64, sb64 := signWithTestTrust(t, manifestBytes)

	err := s.dispatchSignedMutation(context.Background(), mutation(t, "instance.upsert", map[string]any{
		"instance_id":      "inst-1",
		"template_id":      "whoami",
		"user_config":      map[string]any{"name": "blog"},
		"manifest_b64":     mb64,
		"manifest_sig_b64": sb64,
	}))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if spy.count != 1 {
		t.Errorf("reconcile should be triggered once, got %d", spy.count)
	}
	inst, err := st.GetInstance(context.Background(), "inst-1")
	if err != nil {
		t.Fatalf("instance not stored: %v", err)
	}
	if inst.Runtime != store.RuntimeContainer || inst.Version != "1.2.3" {
		t.Errorf("stored wrong: runtime=%s version=%s", inst.Runtime, inst.Version)
	}
	if inst.DesiredState != store.DesiredInstalled {
		t.Errorf("desired state: %s", inst.DesiredState)
	}
}

func TestDispatchInstanceUpsertRejectsUnsigned(t *testing.T) {
	s, _, spy := newDispatchSyncer(t)
	err := s.dispatchSignedMutation(context.Background(), mutation(t, "instance.upsert", map[string]any{
		"instance_id": "inst-1",
		"template_id": "whoami",
	}))
	if err == nil {
		t.Fatal("unsigned instance.upsert must be rejected")
	}
	if spy.count != 0 {
		t.Error("no reconcile on rejection")
	}
}

func TestDispatchInstanceUpsertRejectsBadSignature(t *testing.T) {
	s, _, _ := newDispatchSyncer(t)
	manifestBytes := []byte(containerTestManifest)
	mb64, sb64 := signWithTestTrust(t, manifestBytes)
	// Tamper the manifest after signing: same sig, different bytes.
	tampered := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(containerTestManifest, "traefik/whoami:latest", "evil/miner:latest")))
	err := s.dispatchSignedMutation(context.Background(), mutation(t, "instance.upsert", map[string]any{
		"instance_id":      "inst-1",
		"template_id":      "whoami",
		"manifest_b64":     tampered,
		"manifest_sig_b64": sb64,
	}))
	if err == nil {
		t.Fatal("tampered manifest must be rejected")
	}
	_ = mb64
}

func TestDispatchInstanceUpsertRejectsSystemRuntime(t *testing.T) {
	s, _, _ := newDispatchSyncer(t)
	sysManifest := []byte(`apiVersion: obacht.dev/v2
metadata:
  version: "1.0.0"
spec:
  runtime:
    type: system
    system:
      unitName: foo.service
`)
	mb64, sb64 := signWithTestTrust(t, sysManifest)
	err := s.dispatchSignedMutation(context.Background(), mutation(t, "instance.upsert", map[string]any{
		"instance_id":      "inst-1",
		"template_id":      "foo",
		"manifest_b64":     mb64,
		"manifest_sig_b64": sb64,
	}))
	if err == nil || !strings.Contains(err.Error(), "system-runtime") {
		t.Fatalf("system-runtime template must be rejected, got %v", err)
	}
}

func TestDispatchInstanceSetStateAndDelete(t *testing.T) {
	s, st, _ := newDispatchSyncer(t)
	ctx := context.Background()
	// seed an instance
	if err := st.UpsertInstance(ctx, store.Instance{
		ID: "inst-1", TemplateID: "whoami", Runtime: store.RuntimeContainer,
		Version: "1.0.0", DesiredState: store.DesiredInstalled,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.dispatchSignedMutation(ctx, mutation(t, "instance.set_state", map[string]any{
		"instance_id": "inst-1", "desired_state": "stopped",
	})); err != nil {
		t.Fatalf("set_state: %v", err)
	}
	inst, _ := st.GetInstance(ctx, "inst-1")
	if inst.DesiredState != store.DesiredStopped {
		t.Errorf("state not stopped: %s", inst.DesiredState)
	}
	if err := s.dispatchSignedMutation(ctx, mutation(t, "instance.delete", map[string]any{
		"instance_id": "inst-1",
	})); err != nil {
		t.Fatalf("delete: %v", err)
	}
	inst, _ = st.GetInstance(ctx, "inst-1")
	if inst.DesiredState != store.DesiredRemoved {
		t.Errorf("state not removed: %s", inst.DesiredState)
	}
}

func TestDispatchBindingUpsertDelete(t *testing.T) {
	s, st, _ := newDispatchSyncer(t)
	ctx := context.Background()
	// Bindings FK domain + instance — both exist in the real flow (domain
	// claimed, instance installed) before a bind. Seed them.
	if err := st.UpsertDomain(ctx, "blog.example.com", store.DomainStatusReady); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertInstance(ctx, store.Instance{
		ID: "inst-1", TemplateID: "whoami", Runtime: store.RuntimeContainer,
		Version: "1.0.0", DesiredState: store.DesiredInstalled,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.dispatchSignedMutation(ctx, mutation(t, "binding.upsert", map[string]any{
		"domain": "blog.example.com", "instance_id": "inst-1", "service": "web",
	})); err != nil {
		t.Fatalf("binding.upsert: %v", err)
	}
	binds, _ := st.ListBindings(ctx)
	if len(binds) != 1 || binds[0].Domain != "blog.example.com" {
		t.Fatalf("binding not stored: %#v", binds)
	}
	if err := s.dispatchSignedMutation(ctx, mutation(t, "binding.delete", map[string]any{
		"domain": "blog.example.com",
	})); err != nil {
		t.Fatalf("binding.delete: %v", err)
	}
	binds, _ = st.ListBindings(ctx)
	if len(binds) != 0 {
		t.Errorf("binding not deleted: %#v", binds)
	}
}

const containerTestManifest = `apiVersion: obacht.dev/v2
kind: TemplateManifest
metadata:
  name: whoami
  version: "1.2.3"
spec:
  runtime:
    type: container
    container:
      image: traefik/whoami:latest
      cmd: ["--name=${cfg.name}"]
  services:
    - name: web
      targetPort: 80
  configSchema:
    - key: name
      type: text
      default: hello
`
