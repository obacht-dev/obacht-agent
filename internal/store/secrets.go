package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// CreateInstanceSecret generates and stores a 32-byte random secret for the
// given instance, returning the hex-encoded value. Re-issuing replaces the
// previous secret atomically.
func (s *Store) CreateInstanceSecret(ctx context.Context, instanceID string) (string, error) {
	if instanceID == "" {
		return "", fmt.Errorf("instance id is required")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO instance_secrets(instance_id, secret, created_at) VALUES(?, ?, strftime('%s','now'))
		ON CONFLICT(instance_id) DO UPDATE SET secret = excluded.secret`,
		instanceID, secret)
	if err != nil {
		return "", fmt.Errorf("store secret: %w", err)
	}
	return secret, nil
}

// EnsureInstanceSecret returns the existing secret for an instance, or
// generates+persists one if none exists. Idempotent — safe to call from
// every reconcile pass without churning the secret (which would otherwise
// invalidate container config hashes and trigger needless restarts).
func (s *Store) EnsureInstanceSecret(ctx context.Context, instanceID string) (string, error) {
	if instanceID == "" {
		return "", fmt.Errorf("instance id is required")
	}
	var existing string
	err := s.db.QueryRowContext(ctx,
		`SELECT secret FROM instance_secrets WHERE instance_id = ?`,
		instanceID,
	).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("lookup secret: %w", err)
	}
	return s.CreateInstanceSecret(ctx, instanceID)
}

// LookupInstanceBySecret returns the instance id whose secret matches, or
// ErrNotFound.
func (s *Store) LookupInstanceBySecret(ctx context.Context, secret string) (string, error) {
	if secret == "" {
		return "", ErrNotFound
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT instance_id FROM instance_secrets WHERE secret = ?`, secret).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return id, nil
}
