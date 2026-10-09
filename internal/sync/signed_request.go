package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/signedmut"
)

// SignedRequestsCapability is advertised in agent:register when the agent
// enforces user signatures on log and file requests. Clients sign those
// requests only for devices that advertise it (older agents would ignore
// the envelope but also not require it).
const SignedRequestsCapability = "signed-requests.v1"

// ErrSignatureRequired is returned when a log/file request arrives without
// a signed envelope.
var ErrSignatureRequired = errors.New("signature required: sign this request with your key")

// AuthorizeRequest verifies that a log or file request was signed by a
// locally pinned user key and that the signed op and params are exactly the
// request the backend relayed. It is the gate for agent:logs_request and
// agent:files_request, which used to run on the backend's word alone.
//
// The same envelope format, verifier, device binding, expiry window and
// persistent nonce store as agent:signed_mutation apply, so a compromised
// backend can neither forge such a request nor replay or alter one it saw.
func (s *Syncer) AuthorizeRequest(ctx context.Context, envelope json.RawMessage, op string, params map[string]any) error {
	verifier := s.getVerifier()
	if verifier == nil || verifier.KeyCount() == 0 {
		s.auditSignedMutation(ctx, signedmut.DenyUntrustedKey, op, "", "no user keys pinned", nil)
		return errors.New("device has no pinned user keys")
	}
	if len(envelope) == 0 || string(envelope) == "null" {
		s.auditSignedMutation(ctx, signedmut.DenyMalformed, op, "", "unsigned request", nil)
		return ErrSignatureRequired
	}
	m, key, err := verifier.Verify(ctx, envelope, s.deviceID, time.Now(), s.store)
	if err != nil {
		reason := signedmut.DenyMalformed
		var de *signedmut.DenyError
		if errors.As(err, &de) {
			reason = de.Reason
		}
		label := ""
		if key != nil {
			label = key.Label
		}
		s.auditSignedMutation(ctx, reason, op, label, err.Error(), nil)
		return fmt.Errorf("request rejected: %s", reason)
	}
	if m.Op != op {
		s.auditSignedMutation(ctx, "deny_op_mismatch", op, key.Label, "signed op "+m.Op, m)
		return fmt.Errorf("request rejected: signed op %q does not match %q", m.Op, op)
	}
	ok, err := signedmut.ParamsMatch(m.Params, params)
	if err != nil || !ok {
		s.auditSignedMutation(ctx, "deny_params_mismatch", op, key.Label, "signed params differ from request", m)
		return errors.New("request rejected: signed params do not match the request")
	}
	s.auditSignedMutation(ctx, "ok", op, key.Label, "", m)
	return nil
}
