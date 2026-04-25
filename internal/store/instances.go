package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Runtime kind for an instance.
type Runtime string

const (
	RuntimeContainer Runtime = "container"
	RuntimeSystem    Runtime = "system"
)

// DesiredState for an instance.
type DesiredState string

const (
	DesiredInstalled DesiredState = "installed"
	DesiredStopped   DesiredState = "stopped"
	DesiredRemoved   DesiredState = "removed"
)

// Instance represents one row in the `instances` table.
type Instance struct {
	ID            string
	TemplateID    string
	Runtime       Runtime
	Version       string
	DesiredState  DesiredState
	ConfigJSON    string
	ObservedState string // free-form, last value pushed by runtime/template ("running", "stopped", "error", ...)
	ObservedJSON  string
	ObservedAt    time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ErrNotFound is returned by Get* methods when the row is missing.
var ErrNotFound = errors.New("not found")

// UpsertInstance inserts a new instance row or updates the mutable fields of
// an existing one (everything except `id` and `created_at`).
func (s *Store) UpsertInstance(ctx context.Context, inst Instance) error {
	if inst.ID == "" || inst.TemplateID == "" || inst.Runtime == "" || inst.DesiredState == "" {
		return fmt.Errorf("upsert instance: id, template_id, runtime, desired_state are required")
	}
	now := time.Now().Unix()
	if inst.CreatedAt.IsZero() {
		inst.CreatedAt = time.Unix(now, 0)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO instances(id, template_id, runtime, version, desired_state, config_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			template_id   = excluded.template_id,
			runtime       = excluded.runtime,
			version       = excluded.version,
			desired_state = excluded.desired_state,
			config_json   = excluded.config_json,
			updated_at    = excluded.updated_at
	`, inst.ID, inst.TemplateID, string(inst.Runtime), inst.Version, string(inst.DesiredState), inst.ConfigJSON, inst.CreatedAt.Unix(), now)
	if err != nil {
		return fmt.Errorf("upsert instance %s: %w", inst.ID, err)
	}
	return nil
}

// GetInstance returns the instance with the given id, or ErrNotFound.
func (s *Store) GetInstance(ctx context.Context, id string) (*Instance, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, template_id, runtime, version, desired_state, COALESCE(config_json,''),
		       COALESCE(observed_state,''), COALESCE(observed_json,''), COALESCE(observed_at,0),
		       created_at, updated_at
		FROM instances WHERE id = ?`, id)
	return scanInstance(row)
}

// ListInstances returns all instances regardless of desired state.
func (s *Store) ListInstances(ctx context.Context) ([]Instance, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, template_id, runtime, version, desired_state, COALESCE(config_json,''),
		       COALESCE(observed_state,''), COALESCE(observed_json,''), COALESCE(observed_at,0),
		       created_at, updated_at
		FROM instances ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		inst, err := scanInstanceFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inst)
	}
	return out, rows.Err()
}

// DeleteInstance removes an instance row (cascades to dependent tables).
func (s *Store) DeleteInstance(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM instances WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete instance %s: %w", id, err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanInstance(r rowScanner) (*Instance, error) {
	inst, err := readInstance(r)
	if err != nil {
		return nil, err
	}
	return inst, nil
}

func scanInstanceFromRows(rows *sql.Rows) (*Instance, error) {
	return readInstance(rows)
}

func readInstance(r rowScanner) (*Instance, error) {
	var (
		i                Instance
		runtime          string
		desiredState     string
		observedAt       int64
		createdAt, ua    int64
	)
	if err := r.Scan(&i.ID, &i.TemplateID, &runtime, &i.Version, &desiredState, &i.ConfigJSON,
		&i.ObservedState, &i.ObservedJSON, &observedAt, &createdAt, &ua); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	i.Runtime = Runtime(runtime)
	i.DesiredState = DesiredState(desiredState)
	if observedAt > 0 {
		i.ObservedAt = time.Unix(observedAt, 0)
	}
	i.CreatedAt = time.Unix(createdAt, 0)
	i.UpdatedAt = time.Unix(ua, 0)
	return &i, nil
}

// SetObservedState records the latest observed state for an instance.
// payload is an opaque JSON blob (or empty string).
func (s *Store) SetObservedState(ctx context.Context, instanceID, state, payload string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE instances
		   SET observed_state = ?, observed_json = ?, observed_at = ?
		 WHERE id = ?`, state, payload, time.Now().Unix(), instanceID)
	return err
}

// SetMeta upserts a key/value pair into agent_meta.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// GetMeta reads a key from agent_meta. Returns ErrNotFound if missing.
func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM agent_meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}
