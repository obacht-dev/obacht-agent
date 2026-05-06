package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// TemplateSecret is one per-instance, per-key generated secret.
type TemplateSecret struct {
	InstanceID string
	Key        string
	Value      string
	Length     int
	Charset    string
}

const (
	CharsetAlphanumeric        = "alphanumeric"
	CharsetAlphanumericSymbols = "alphanumeric_symbols"
	CharsetHex                 = "hex"
	CharsetBase64              = "base64"
	// CharsetBase64Bytes means: generate `length` raw random bytes and emit
	// them as standard padded base64. The resulting string is therefore
	// longer than `length` chars (about 4*ceil(length/3)). Use this when
	// the consumer (e.g. Laravel APP_KEY) requires the decoded payload to
	// be exactly `length` bytes long.
	CharsetBase64Bytes = "base64_bytes"
)

const (
	alphanumericChars        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alphanumericSymbolsChars = alphanumericChars + "!@#$%^&*-_=+"
)

// GenerateSecretValue generates `length` bytes of secret material with the
// requested charset. Exposed package-level so unit tests + the compose
// runtime's secret-replay can share the implementation.
func GenerateSecretValue(charset string, length int) (string, error) {
	if length < 8 || length > 256 {
		return "", fmt.Errorf("length must be 8..256, got %d", length)
	}
	switch charset {
	case "", CharsetAlphanumeric:
		return randString(alphanumericChars, length)
	case CharsetAlphanumericSymbols:
		return randString(alphanumericSymbolsChars, length)
	case CharsetHex:
		buf := make([]byte, (length+1)/2)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		return hex.EncodeToString(buf)[:length], nil
	case CharsetBase64:
		buf := make([]byte, length)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		return base64.RawStdEncoding.EncodeToString(buf)[:length], nil
	case CharsetBase64Bytes:
		buf := make([]byte, length)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(buf), nil
	default:
		return "", fmt.Errorf("unknown charset %q", charset)
	}
}

func randString(alphabet string, n int) (string, error) {
	out := make([]byte, n)
	max := len(alphabet)
	buf := make([]byte, n*2) // generous oversample to avoid bias loop
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	bi := 0
	for i := 0; i < n; i++ {
		// Re-fill if we somehow exhaust the buffer (extremely unlikely).
		if bi >= len(buf) {
			if _, err := rand.Read(buf); err != nil {
				return "", err
			}
			bi = 0
		}
		out[i] = alphabet[int(buf[bi])%max]
		bi++
	}
	return string(out), nil
}

// EnsureTemplateSecret returns the existing secret value for
// (instanceID, key) or generates+persists one. Idempotent across reconcile
// passes — calling it doesn't churn the value.
func (s *Store) EnsureTemplateSecret(ctx context.Context, instanceID, key, charset string, length int) (string, error) {
	if instanceID == "" || key == "" {
		return "", fmt.Errorf("instance id and key are required")
	}
	var existing string
	err := s.db.QueryRowContext(ctx,
		`SELECT secret_val FROM template_secrets WHERE instance_id = ? AND secret_key = ?`,
		instanceID, key,
	).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("lookup template secret: %w", err)
	}
	val, err := GenerateSecretValue(charset, length)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO template_secrets(instance_id, secret_key, secret_val, charset, length, created_at)
		 VALUES (?, ?, ?, ?, ?, strftime('%s','now'))`,
		instanceID, key, val, charset, length,
	)
	if err != nil {
		return "", fmt.Errorf("insert template secret: %w", err)
	}
	return val, nil
}

// DropTemplateSecrets removes every secret tied to an instance. Called
// when an instance is destroyed (DesiredRemoved → reconciled → deleted).
func (s *Store) DropTemplateSecrets(ctx context.Context, instanceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM template_secrets WHERE instance_id = ?`, instanceID)
	if err != nil {
		return fmt.Errorf("drop template secrets: %w", err)
	}
	return nil
}

// ListTemplateSecretKeys returns just the keys (not values) for diagnostic
// CLIs / audit. Values are never logged.
func (s *Store) ListTemplateSecretKeys(ctx context.Context, instanceID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT secret_key FROM template_secrets WHERE instance_id = ? ORDER BY secret_key`,
		instanceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
