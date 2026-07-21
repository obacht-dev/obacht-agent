package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/manifest"
	"github.com/obacht-dev/obacht-agent/internal/signedmut"
	"github.com/obacht-dev/obacht-agent/internal/store"
)

// IngressManager is the subset of internal/ingress the signed-mutation
// dispatcher needs (same shape as internal/ipc.IngressManager).
type IngressManager interface {
	Reload(ctx context.Context) error
}

// SetSignedMutations wires the verifier (pinned user keys) and the ingress
// manager. When the verifier holds at least one key, sendRegister advertises
// the "signed-mutation" capability and the agent:signed_mutation handler
// dispatches verified ops. Without it the event is denied like any other
// inbound mutation.
func (s *Syncer) SetSignedMutations(v *signedmut.Verifier, ing IngressManager) {
	s.verifierMu.Lock()
	s.verifier = v
	s.verifierMu.Unlock()
	s.ingress = ing
}

// getVerifier returns the current verifier snapshot. Handlers must read the
// verifier through this so a concurrent ReloadUserKeys swap is safe.
func (s *Syncer) getVerifier() *signedmut.Verifier {
	s.verifierMu.RLock()
	defer s.verifierMu.RUnlock()
	return s.verifier
}

// ReloadUserKeys re-reads the pinned user keys from dir, swaps the verifier
// in place and — when connected — immediately re-registers so the backend
// sees the capability flip without an agent restart. Called from the IPC
// user-keys handlers after obachtctl pins or unpins a key.
func (s *Syncer) ReloadUserKeys(dir string) (int, []error) {
	keys, problems := signedmut.LoadUserKeys(dir)
	s.verifierMu.Lock()
	s.verifier = signedmut.NewVerifier(keys)
	s.verifierMu.Unlock()
	s.log.Info("user keys reloaded", "count", len(keys))
	if s.client.Connected() {
		s.sendRegister()
	}
	return len(keys), problems
}

// Reregister re-emits agent:register when connected. Used by the IPC layer
// after system-setting flips (power_mode gates the runtime.system
// capability) — mirror of the ReloadUserKeys re-register behaviour.
func (s *Syncer) Reregister() {
	if s.client.Connected() {
		s.sendRegister()
	}
}

// signedMutationOpTimeout bounds a single mutation dispatch (store writes +
// Caddy reload are local and fast; this only guards against a wedged docker).
const signedMutationOpTimeout = 30 * time.Second

// handleSignedMutation is the WS handler for `agent:signed_mutation`.
//
// SECURITY: this is the ONLY inbound event that may mutate state, and only
// after signedmut.Verify accepted the envelope: signature by a locally
// pinned user key over the JCS-canonical mutation, device binding, expiry
// window, fresh nonce. The unsigned agent:upsert_*/delete_* events stay on
// the deny list forever — see Run().
func (s *Syncer) handleSignedMutation(args []json.RawMessage) {
	if len(args) == 0 {
		return
	}
	raw := []byte(args[0])
	ctx, cancel := context.WithTimeout(context.Background(), signedMutationOpTimeout)
	defer cancel()

	// Best-effort nonce/op extraction for result correlation. Untrusted
	// until Verify passes — used only to label the result/audit events.
	var peek struct {
		Mutation struct {
			Op    string `json:"op"`
			Nonce string `json:"nonce"`
		} `json:"mutation"`
	}
	_ = json.Unmarshal(raw, &peek)

	verifier := s.getVerifier()
	if verifier == nil || verifier.KeyCount() == 0 {
		s.auditSignedMutation(ctx, signedmut.DenyUntrustedKey, peek.Mutation.Op, "", "no user keys pinned", nil)
		s.emitSignedMutationResult(peek.Mutation.Nonce, peek.Mutation.Op, false, "device has no pinned user keys")
		return
	}

	m, key, err := verifier.Verify(ctx, raw, s.deviceID, time.Now(), s.store)
	if err != nil {
		reason := signedmut.DenyMalformed
		var de *signedmut.DenyError
		if errors.As(err, &de) {
			reason = de.Reason
		}
		keyLabel := ""
		if key != nil {
			keyLabel = key.Label
		}
		s.log.Warn("signed mutation rejected", "reason", reason, "op", peek.Mutation.Op, "err", err)
		s.auditSignedMutation(ctx, reason, peek.Mutation.Op, keyLabel, err.Error(), nil)
		s.emitSignedMutationResult(peek.Mutation.Nonce, peek.Mutation.Op, false, reason)
		return
	}

	opErr := s.dispatchSignedMutation(ctx, m)
	if opErr != nil {
		s.log.Warn("signed mutation dispatch failed", "op", m.Op, "err", opErr)
		s.auditSignedMutation(ctx, "error", m.Op, key.Label, opErr.Error(), m)
		s.emitSignedMutationResult(m.Nonce, m.Op, false, opErr.Error())
		return
	}
	s.log.Info("signed mutation applied", "op", m.Op, "key", key.Label, "nonce", m.Nonce)
	s.auditSignedMutation(ctx, "ok", m.Op, key.Label, "", m)
	s.emitSignedMutationResult(m.Nonce, m.Op, true, "")
}

// dispatchSignedMutation routes a VERIFIED mutation to the same internal
// mutators obachtctl drives over IPC. Ops not in this table are rejected —
// growing it is a deliberate, reviewed act (stage 0: domain ops only).
func (s *Syncer) dispatchSignedMutation(ctx context.Context, m *signedmut.Mutation) error {
	switch m.Op {
	case "domain.upsert":
		var p struct {
			Domain  string `json:"domain"`
			Desired string `json:"desired_status"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return errors.New("invalid params for domain.upsert")
		}
		if err := s.store.UpsertDomain(ctx, p.Domain, p.Desired); err != nil {
			return err
		}
		if s.ingress != nil {
			_ = s.ingress.Reload(ctx)
		}
		s.rec.Trigger()
		return nil

	case "domain.delete":
		var p struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil || p.Domain == "" {
			return errors.New("invalid params for domain.delete")
		}
		if err := s.store.DeleteDomain(ctx, p.Domain); err != nil {
			return err
		}
		s.rec.Trigger()
		return nil

	case "instance.upsert":
		return s.dispatchInstanceUpsert(ctx, m)

	case "instance.delete":
		var p struct {
			InstanceID string `json:"instance_id"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil || p.InstanceID == "" {
			return errors.New("invalid params for instance.delete")
		}
		// Soft delete — mark removed, let the reconciler tear down (mirrors
		// the IPC default; a hard delete would orphan the running container).
		inst, err := s.store.GetInstance(ctx, p.InstanceID)
		if err != nil {
			return err
		}
		inst.DesiredState = store.DesiredRemoved
		if err := s.store.UpsertInstance(ctx, *inst); err != nil {
			return err
		}
		s.rec.Trigger()
		return nil

	case "instance.set_state":
		var p struct {
			InstanceID string `json:"instance_id"`
			State      string `json:"desired_state"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil || p.InstanceID == "" {
			return errors.New("invalid params for instance.set_state")
		}
		switch p.State {
		case string(store.DesiredInstalled), string(store.DesiredStopped):
		default:
			return fmt.Errorf("desired_state must be 'installed' or 'stopped', got %q", p.State)
		}
		inst, err := s.store.GetInstance(ctx, p.InstanceID)
		if err != nil {
			return err
		}
		inst.DesiredState = store.DesiredState(p.State)
		if err := s.store.UpsertInstance(ctx, *inst); err != nil {
			return err
		}
		s.rec.Trigger()
		return nil

	case "binding.upsert":
		var p struct {
			Domain      string `json:"domain"`
			InstanceID  string `json:"instance_id"`
			ServiceName string `json:"service"`
			LocalPort   int    `json:"local_port"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil || p.Domain == "" {
			return errors.New("invalid params for binding.upsert")
		}
		if err := s.store.UpsertBinding(ctx, store.IngressBinding{
			Domain:      p.Domain,
			InstanceID:  p.InstanceID,
			ServiceName: p.ServiceName,
			LocalPort:   p.LocalPort,
		}); err != nil {
			return err
		}
		s.rec.Trigger()
		return nil

	case "binding.delete":
		var p struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil || p.Domain == "" {
			return errors.New("invalid params for binding.delete")
		}
		if err := s.store.DeleteBinding(ctx, p.Domain); err != nil {
			return err
		}
		s.rec.Trigger()
		return nil

	default:
		return errors.New("unsupported op " + m.Op)
	}
}

// dispatchInstanceUpsert installs/reconfigures a template instance from a
// VERIFIED signed mutation. This is the path Mac template installs take
// instead of obachtctl-over-SSH, so it must enforce the SAME trust chain:
//
//  1. the USER signature over the envelope is already verified by the
//     caller (Verify) — the manifest bytes inside are thus user-attested;
//  2. the manifest's own minisign signature is verified here against the
//     embedded registry trust bundle (a compromised backend can neither
//     forge the user sig nor the registry sig — both must hold, I4);
//  3. system-runtime templates are rejected — EXCEPT the macOS host-service
//     flavor (launchd on the host, e.g. Ollama) on darwin, which Phase 5
//     wires up; systemd system templates stay rejected (no systemd in the VM);
//  4. power-mode templates are rejected (not wired yet);
//  5. the manifest is materialised through the SAME code obachtctl uses
//     (internal/manifest.BuildInstanceConfig) — no drift.
func (s *Syncer) dispatchInstanceUpsert(ctx context.Context, m *signedmut.Mutation) error {
	var p struct {
		InstanceID     string         `json:"instance_id"`
		TemplateID     string         `json:"template_id"`
		Version        string         `json:"version"`
		DesiredState   string         `json:"desired_state"`
		UserConfig     map[string]any `json:"user_config"`
		ManifestB64    string         `json:"manifest_b64"`
		ManifestSigB64 string         `json:"manifest_sig_b64"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return errors.New("invalid params for instance.upsert")
	}
	if p.InstanceID == "" || p.TemplateID == "" {
		return errors.New("instance_id and template_id are required")
	}
	if p.ManifestB64 == "" || p.ManifestSigB64 == "" {
		// The signed path is strict: no ALLOW_UNSIGNED fallback. A template
		// install must carry the registry-signed manifest bytes.
		return errors.New("signed manifest (manifest_b64 + manifest_sig_b64) is required")
	}
	manifestBytes, err := manifest.DecodeBase64(p.ManifestB64)
	if err != nil {
		return fmt.Errorf("manifest_b64 not valid base64: %w", err)
	}
	sig, err := manifest.DecodeBase64(p.ManifestSigB64)
	if err != nil {
		return fmt.Errorf("manifest_sig_b64 not valid base64: %w", err)
	}
	if err := manifest.Verify(manifestBytes, sig, manifest.TrustDir()); err != nil {
		return fmt.Errorf("manifest signature rejected: %w", err)
	}
	if rt := manifest.RuntimeType(manifestBytes); rt == "system" {
		// Which system flavor is allowed on THIS device via the signed path:
		//   - darwin: the macOS host-service (launchd, e.g. Ollama).
		//   - linux (Pi): the v2.8 managed-service + kiosk flavors, which the
		//     reconciler/driver run through the hardened-unit + root-helper
		//     path. Requires Power Mode (re-checked below).
		// The withdrawn free-form systemd flavor and any other shape stay
		// rejected.
		darwinHostSvc := runtime.GOOS == "darwin" && manifest.HasHostService(manifestBytes)
		linuxSystem := runtime.GOOS == "linux" &&
			(manifest.HasManagedService(manifestBytes) || manifest.HasKiosk(manifestBytes))
		if !darwinHostSvc && !linuxSystem {
			return errors.New("system-runtime templates are not supported on this device")
		}
		// Singleton enforcement: host-services bind a fixed host resource, so a
		// second instance of the same template can never run. Reject a duplicate
		// install (different instance id, same template). Re-upserting the SAME
		// instance id (config/version update) is fine. Linux managed_service/
		// kiosk singletons are enforced by the reconciler's exclusivityGroup
		// lock, so this guard is scoped to the host-service flavor.
		if darwinHostSvc {
			if desired := store.DesiredState(p.DesiredState); desired != store.DesiredRemoved {
				existing, err := s.store.ListInstances(ctx)
				if err != nil {
					return fmt.Errorf("check existing host-services: %w", err)
				}
				for _, e := range existing {
					if e.Runtime == store.RuntimeSystem && e.TemplateID == p.TemplateID &&
						e.ID != p.InstanceID && e.DesiredState != store.DesiredRemoved {
						return fmt.Errorf("host-service %q is already installed on this device (instance %s); remove it before installing another", p.TemplateID, e.ID)
					}
				}
			}
		}
	}
	if manifest.ExtractMinSudoLevel(manifestBytes) == "power" {
		// Power-mode templates (Pi system runtime) are allowed on the signed
		// path only when Power Mode is actually unlocked on this device — the
		// same on-device gate obachtctl enforces. The reconciler/driver/helper
		// enforce all the confinement beyond this point.
		if runtime.GOOS != "linux" || !s.powerModeEnabled() {
			return errors.New("this template requires Power Mode — unlock it in the device settings first")
		}
	}

	built, err := manifest.BuildInstanceConfig(manifestBytes, p.UserConfig, p.InstanceID, p.TemplateID, p.Version)
	if err != nil {
		return err
	}
	cfgJSON, err := json.Marshal(built.Config)
	if err != nil {
		return fmt.Errorf("encode materialised config: %w", err)
	}
	desired := store.DesiredInstalled
	if p.DesiredState != "" {
		desired = store.DesiredState(p.DesiredState)
	}
	if err := s.store.UpsertInstance(ctx, store.Instance{
		ID:           p.InstanceID,
		TemplateID:   p.TemplateID,
		Runtime:      store.Runtime(built.Runtime),
		Version:      built.Version,
		DesiredState: desired,
		ConfigJSON:   string(cfgJSON),
	}); err != nil {
		return err
	}
	s.rec.Trigger()
	return nil
}

func (s *Syncer) auditSignedMutation(ctx context.Context, outcome, op, keyLabel, errMsg string, m *signedmut.Mutation) {
	e := audit.Entry{
		Op:     "security.signed_mutation." + outcome,
		Actor:  "user",
		Target: op,
		Params: map[string]any{},
	}
	if keyLabel != "" {
		e.Actor = "user:" + keyLabel
	}
	if m != nil {
		e.Params["nonce"] = m.Nonce
		// Params of accepted mutations are not secret-shaped today
		// (domain names + status), but keep this a summary, not a dump,
		// so a future op can't accidentally leak config into the audit log.
		e.ParamsSummary = m.Op
	}
	switch outcome {
	case "ok":
		e.Result = audit.ResultOK
	case "error":
		e.Result = audit.ResultError
		e.ErrorMessage = errMsg
	default:
		e.Result = audit.ResultDenied
		e.ErrorMessage = errMsg
	}
	_ = s.audit.Append(ctx, e)
}

func (s *Syncer) emitSignedMutationResult(nonce, op string, ok bool, errMsg string) {
	payload := map[string]any{
		"deviceId": s.deviceID,
		"nonce":    nonce,
		"op":       op,
		"ok":       ok,
	}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	if err := s.client.Emit("agent:signed_mutation_result", payload); err != nil {
		s.log.Debug("emit signed_mutation_result", "err", err)
	}
}
