// Package enckey manages the device's X25519 encryption identity
// (ANALYSE-E2E-PARAMS-ENCRYPTION-2026-08-15 §4, Schritt 2).
//
// The agent has no asymmetric keypair of its own (identity = device_id +
// JWT; minisign keys are verify-only). This package creates one so that
// clients can eventually encrypt secret-typed config values TO the device
// instead of sending them in plaintext through the backend relay.
//
// This release only ESTABLISHES and PUBLISHES the key (capability
// `enc-key.v1` in agent:register). Accepting encrypted params is a later,
// separate capability (`enc-params.v1`) so no client ever encrypts against
// an agent that cannot decrypt.
//
// The private key lives in agent_meta (agent-v2.db) — same storage class
// as template_secrets: device-local plaintext SQLite, mode-restricted.
package enckey

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// metaPrivKey is the agent_meta key holding the base64 raw X25519 private
// key (32 bytes).
const metaPrivKey = "enc_x25519_priv_b64"

// Capability advertised in agent:register once the keypair exists.
const Capability = "enc-key.v1"

// MetaStore is the slice of *store.Store this package needs.
type MetaStore interface {
	GetMeta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error
}

// EnsurePublicKey returns the base64 raw 32-byte X25519 public key,
// generating and persisting the keypair on first call. Safe to call on
// every register — after the first call it is a single meta read.
func EnsurePublicKey(ctx context.Context, s MetaStore) (string, error) {
	curve := ecdh.X25519()
	if b64, err := s.GetMeta(ctx, metaPrivKey); err == nil && b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err == nil {
			if priv, err := curve.NewPrivateKey(raw); err == nil {
				return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
			}
		}
		// Corrupt stored key: fall through and regenerate. Nothing is
		// durably encrypted to this key (transport-only design), so a
		// regenerate is always safe.
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate x25519 key: %w", err)
	}
	if err := s.SetMeta(ctx, metaPrivKey, base64.StdEncoding.EncodeToString(priv.Bytes())); err != nil {
		return "", fmt.Errorf("persist x25519 key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// Fingerprint returns the display fingerprint of a base64 raw public key,
// in the same SHA256:<base64-no-padding> shape as OpenSSH key fingerprints
// so the webapp/obachtctl can render both key kinds uniformly.
func Fingerprint(pubB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}
