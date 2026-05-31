package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
//
// SEC-27: the match is done with a constant-time comparison rather than a SQL
// `WHERE secret = ?` equality, so the lookup time does not leak how many
// leading bytes of a guessed token were correct. The instance_secrets table
// holds at most one row per running instance (a handful), so scanning all
// rows is cheap.
func (s *Store) LookupInstanceBySecret(ctx context.Context, secret string) (string, error) {
	if secret == "" {
		return "", ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT instance_id, secret FROM instance_secrets`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	want := []byte(secret)
	matchedID := ""
	found := false
	for rows.Next() {
		var id, stored string
		if err := rows.Scan(&id, &stored); err != nil {
			return "", err
		}
		// Constant-time compare; keep scanning every row so total work does
		// not depend on which (if any) row matched.
		if subtle.ConstantTimeCompare([]byte(stored), want) == 1 {
			matchedID = id
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if !found {
		return "", ErrNotFound
	}
	return matchedID, nil
}
