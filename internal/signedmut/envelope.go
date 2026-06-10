package signedmut

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Wire format (matches the webapp's signed-mutations lib and the relay DTO
// in obacht-api — field names are part of the protocol, v:1):
//
//	envelope = {
//	  mutation: { v:1, device_id, op, params, nonce, iat, exp, key_id },
//	  sig_b64:            base64(ed25519.sign(sk, JCS(mutation))),
//	  signer_pubkey_b64:  base64(raw 32-byte ed25519 pubkey)
//	}

// Envelope keeps the mutation as raw JSON: verification canonicalizes the
// *decoded value tree*, never the wire bytes, so client and agent agree on
// the signed bytes regardless of transport re-encoding.
type Envelope struct {
	Mutation        json.RawMessage `json:"mutation"`
	SigB64          string          `json:"sig_b64"`
	SignerPubkeyB64 string          `json:"signer_pubkey_b64"`
}

// Mutation is the typed view of Envelope.Mutation used after verification.
type Mutation struct {
	V        int             `json:"v"`
	DeviceID string          `json:"device_id"`
	Op       string          `json:"op"`
	Params   json.RawMessage `json:"params"`
	Nonce    string          `json:"nonce"`
	Iat      int64           `json:"iat"`
	Exp      int64           `json:"exp"`
	KeyID    string          `json:"key_id"`
}

// Deny reasons. Audited verbatim as security.signed_mutation.<reason>, so
// keep them stable and grep-friendly.
const (
	DenyMalformed      = "deny_malformed"
	DenyUntrustedKey   = "deny_untrusted_key"
	DenySig            = "deny_sig"
	DenyDeviceMismatch = "deny_device_mismatch"
	DenyExpired        = "deny_expired"
	DenyFutureIat      = "deny_future_iat"
	DenyWindow         = "deny_window"
	DenyReplay         = "deny_replay"
)

// DenyError carries the audit reason alongside the human-readable cause.
type DenyError struct {
	Reason string
	Err    error
}

func (e *DenyError) Error() string { return e.Reason + ": " + e.Err.Error() }
func (e *DenyError) Unwrap() error { return e.Err }

func deny(reason string, err error) *DenyError { return &DenyError{Reason: reason, Err: err} }

// Verification limits.
const (
	maxEnvelopeBytes = 1 << 20 // 1 MiB — instance.upsert carries manifest_b64
	clockSkew        = 30 * time.Second
	maxLifetime      = 10 * time.Minute // sanity cap on exp-iat (clients use 120s)
)

// ReplayStore is the persistent nonce store (implemented by internal/store).
// CheckAndMark must be atomic: it returns true exactly once per nonce.
type ReplayStore interface {
	CheckAndMarkNonce(ctx context.Context, nonce string, now time.Time) (fresh bool, err error)
}

// Verifier holds the pinned user keys. Construct via NewVerifier.
type Verifier struct {
	keys []UserKey
}

// NewVerifier builds a verifier over the pinned user pubkeys. An empty set
// is allowed — Verify then denies everything and the syncer must not
// advertise the signed-mutation capability.
func NewVerifier(keys []UserKey) *Verifier { return &Verifier{keys: keys} }

// KeyCount reports how many user keys are pinned (capability gate).
func (v *Verifier) KeyCount() int { return len(v.keys) }

// KeyLabels returns the pinned key labels for status/diagnostics.
func (v *Verifier) KeyLabels() []string {
	out := make([]string, 0, len(v.keys))
	for _, k := range v.keys {
		out = append(out, k.Label)
	}
	return out
}

// Verify checks the envelope end to end and returns the parsed mutation on
// success. Order matters and mirrors the plan: trusted key → signature →
// device binding → time window → replay. The replay mark is written LAST so
// a mutation that fails any earlier check does not burn its nonce.
func (v *Verifier) Verify(ctx context.Context, raw []byte, ownDeviceID string, now time.Time, replay ReplayStore) (*Mutation, *UserKey, error) {
	if len(raw) > maxEnvelopeBytes {
		return nil, nil, deny(DenyMalformed, fmt.Errorf("envelope exceeds %d bytes", maxEnvelopeBytes))
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, deny(DenyMalformed, fmt.Errorf("decode envelope: %w", err))
	}
	if len(env.Mutation) == 0 || env.SigB64 == "" || env.SignerPubkeyB64 == "" {
		return nil, nil, deny(DenyMalformed, errors.New("mutation, sig_b64 and signer_pubkey_b64 are required"))
	}

	signerPub, err := base64.StdEncoding.DecodeString(env.SignerPubkeyB64)
	if err != nil || len(signerPub) != ed25519.PublicKeySize {
		return nil, nil, deny(DenyMalformed, errors.New("signer_pubkey_b64 is not a raw ed25519 public key"))
	}
	sig, err := base64.StdEncoding.DecodeString(env.SigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, deny(DenyMalformed, errors.New("sig_b64 is not an ed25519 signature"))
	}

	// 1. The signer must be one of the locally pinned user keys. The agent
	// never trusts a key just because the backend forwarded it.
	var matched *UserKey
	for i := range v.keys {
		if bytes.Equal(v.keys[i].Pub, signerPub) {
			matched = &v.keys[i]
			break
		}
	}
	if matched == nil {
		return nil, nil, deny(DenyUntrustedKey, errors.New("signer pubkey is not in the pinned user-key set"))
	}

	// 2. Signature over the JCS canonicalization of the decoded mutation.
	tree, err := decodeJSON(env.Mutation)
	if err != nil {
		return nil, nil, deny(DenyMalformed, fmt.Errorf("decode mutation: %w", err))
	}
	canon, err := canonicalize(tree)
	if err != nil {
		return nil, nil, deny(DenyMalformed, fmt.Errorf("canonicalize mutation: %w", err))
	}
	if !ed25519.Verify(ed25519.PublicKey(signerPub), canon, sig) {
		return nil, matched, deny(DenySig, errors.New("ed25519 signature does not verify over canonical mutation"))
	}

	var m Mutation
	if err := json.Unmarshal(env.Mutation, &m); err != nil {
		return nil, matched, deny(DenyMalformed, fmt.Errorf("parse mutation: %w", err))
	}
	if m.V != 1 {
		return nil, matched, deny(DenyMalformed, fmt.Errorf("unsupported mutation version %d", m.V))
	}
	if m.Op == "" || m.Nonce == "" || len(m.Nonce) > 128 {
		return nil, matched, deny(DenyMalformed, errors.New("op and nonce are required"))
	}

	// 3. Device binding — an envelope signed for another device is invalid
	// here even though the signature itself is fine.
	if m.DeviceID != ownDeviceID {
		return nil, matched, deny(DenyDeviceMismatch, fmt.Errorf("mutation device_id %q != own %q", m.DeviceID, ownDeviceID))
	}

	// 4. Time window.
	nowU := now.Unix()
	if m.Iat > nowU+int64(clockSkew.Seconds()) {
		return nil, matched, deny(DenyFutureIat, fmt.Errorf("iat %d is in the future (now %d)", m.Iat, nowU))
	}
	if m.Exp <= nowU {
		return nil, matched, deny(DenyExpired, fmt.Errorf("exp %d already passed (now %d)", m.Exp, nowU))
	}
	if m.Exp-m.Iat > int64(maxLifetime.Seconds()) || m.Exp <= m.Iat {
		return nil, matched, deny(DenyWindow, fmt.Errorf("implausible validity window iat=%d exp=%d", m.Iat, m.Exp))
	}

	// 5. Replay — last, so failed envelopes don't consume the nonce.
	fresh, err := replay.CheckAndMarkNonce(ctx, m.Nonce, now)
	if err != nil {
		return nil, matched, fmt.Errorf("nonce store: %w", err)
	}
	if !fresh {
		return nil, matched, deny(DenyReplay, fmt.Errorf("nonce %q already seen", m.Nonce))
	}

	return &m, matched, nil
}

// decodeJSON parses raw JSON into the value tree canonicalize() accepts.
// Numbers are kept as json.Number and converted to int64 — any non-integer
// is rejected (see jcs.go for why).
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// Reject trailing garbage after the JSON value.
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	return normalize(v)
}

func normalize(v any) (any, error) {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return nil, fmt.Errorf("non-integer number %q not allowed in mutations", t.String())
		}
		return i, nil
	case map[string]any:
		for k, el := range t {
			n, err := normalize(el)
			if err != nil {
				return nil, err
			}
			t[k] = n
		}
		return t, nil
	case []any:
		for i, el := range t {
			n, err := normalize(el)
			if err != nil {
				return nil, err
			}
			t[i] = n
		}
		return t, nil
	default:
		return v, nil
	}
}
