package sync

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/audit"
	"github.com/obacht-dev/obacht-agent/internal/signedmut"
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
	s.verifier = v
	s.ingress = ing
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

	if s.verifier == nil || s.verifier.KeyCount() == 0 {
		s.auditSignedMutation(ctx, signedmut.DenyUntrustedKey, peek.Mutation.Op, "", "no user keys pinned", nil)
		s.emitSignedMutationResult(peek.Mutation.Nonce, peek.Mutation.Op, false, "device has no pinned user keys")
		return
	}

	m, key, err := s.verifier.Verify(ctx, raw, s.deviceID, time.Now(), s.store)
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

	default:
		return errors.New("unsupported op " + m.Op)
	}
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
