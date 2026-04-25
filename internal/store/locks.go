package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrLockHeld is returned by TryAcquireLock when another instance already
// owns the requested exclusivity group. Callers should surface this as a
// user-visible install error.
var ErrLockHeld = errors.New("exclusivity lock already held")

// TryAcquireLock atomically claims an exclusivity group for the given
// instance. If the group is free, it inserts a row and returns nil.
// If the group is held by a different instance, it returns ErrLockHeld
// (along with the holder id via GetLockHolder). If the group is already
// held by this same instance, it is a no-op (idempotent).
func (s *Store) TryAcquireLock(ctx context.Context, group, instanceID string) error {
	if group == "" || instanceID == "" {
		return fmt.Errorf("group and instance id are required")
	}
	// Check existing holder first so we can return ErrLockHeld with context.
	var holder string
	err := s.db.QueryRowContext(ctx,
		`SELECT instance_id FROM exclusivity_locks WHERE group_name = ?`, group).Scan(&holder)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// not held yet — proceed to insert
	case err != nil:
		return fmt.Errorf("read exclusivity lock %q: %w", group, err)
	default:
		if holder == instanceID {
			return nil // already ours
		}
		return ErrLockHeld
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO exclusivity_locks(group_name, instance_id, created_at)
		VALUES (?, ?, strftime('%s','now'))`, group, instanceID); err != nil {
		// Race: another goroutine inserted between our SELECT and INSERT.
		// SQLite returns a UNIQUE-violation; treat that as ErrLockHeld.
		return ErrLockHeld
	}
	return nil
}

// GetLockHolder returns the instance id currently holding the group, or
// "" if free.
func (s *Store) GetLockHolder(ctx context.Context, group string) (string, error) {
	var holder string
	err := s.db.QueryRowContext(ctx,
		`SELECT instance_id FROM exclusivity_locks WHERE group_name = ?`, group).Scan(&holder)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read exclusivity lock %q: %w", group, err)
	}
	return holder, nil
}

// ReleaseLock drops the lock held by instanceID for the given group. No-op
// if the lock is held by someone else or not held at all.
func (s *Store) ReleaseLock(ctx context.Context, group, instanceID string) error {
	if group == "" || instanceID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM exclusivity_locks WHERE group_name = ? AND instance_id = ?`,
		group, instanceID)
	return err
}

// ReleaseLocksForInstance drops every lock held by the given instance. Used
// when an instance is uninstalled / its row deleted.
func (s *Store) ReleaseLocksForInstance(ctx context.Context, instanceID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM exclusivity_locks WHERE instance_id = ?`, instanceID)
	return err
}
