package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AuditRow mirrors one entry in audit_log_index. Defined here (not in the
// audit package) to keep store API surface self-contained.
type AuditRow struct {
	Seq           int64
	TS            int64
	Op            string
	Actor         string
	Target        string
	Result        string
	ParamsHash    string
	ParamsSummary string
	ErrorMessage  string
}

// InsertAudit appends a row to audit_log_index and returns the auto-assigned
// seq. Defined as a package-level function (not method) so the audit package
// can call it without an import cycle on a typed store interface.
func InsertAudit(ctx context.Context, s *Store, r AuditRow) (int64, error) {
	if s == nil {
		return 0, errors.New("store: nil receiver")
	}
	if r.TS == 0 {
		r.TS = time.Now().Unix()
	}
	if r.Result == "" {
		r.Result = "ok"
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_log_index
		(ts, op, actor, target, result, params_hash, params_summary, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.TS, r.Op, r.Actor, nullIfEmpty(r.Target), r.Result,
		r.ParamsHash, nullIfEmpty(r.ParamsSummary), nullIfEmpty(r.ErrorMessage))
	if err != nil {
		return 0, fmt.Errorf("insert audit: %w", err)
	}
	return res.LastInsertId()
}

// TailAudit returns up to n most recent rows, newest first.
func TailAudit(ctx context.Context, s *Store, n int) ([]AuditRow, error) {
	if s == nil {
		return nil, errors.New("store: nil receiver")
	}
	if n <= 0 {
		n = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT seq, ts, op, actor,
			COALESCE(target,''), result, params_hash,
			COALESCE(params_summary,''), COALESCE(error_message,'')
		FROM audit_log_index ORDER BY seq DESC LIMIT ?`, n)
	if err != nil {
		return nil, fmt.Errorf("tail audit: %w", err)
	}
	defer rows.Close()
	out := make([]AuditRow, 0, n)
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.Seq, &r.TS, &r.Op, &r.Actor, &r.Target,
			&r.Result, &r.ParamsHash, &r.ParamsSummary, &r.ErrorMessage); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditCounters returns aggregate counts grouped by op (for /v1/system/status).
func AuditCounters(ctx context.Context, s *Store) (map[string]int64, error) {
	if s == nil {
		return nil, errors.New("store: nil receiver")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT op, COUNT(1)
		FROM audit_log_index GROUP BY op`)
	if err != nil {
		return nil, fmt.Errorf("audit counters: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var op string
		var n int64
		if err := rows.Scan(&op, &n); err != nil {
			return nil, err
		}
		out[op] = n
	}
	return out, rows.Err()
}

// --- system_settings (key/value) ---

// GetSystemSetting returns the string value for a key. Returns ErrNotFound
// when missing so callers can apply their own defaults.
func (s *Store) GetSystemSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, key).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return v, nil
}

// SetSystemSetting upserts a setting and bumps updated_at.
func (s *Store) SetSystemSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO system_settings(key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now().Unix())
	return err
}

// AllSystemSettings returns all key/value pairs (for /v1/system/status).
func (s *Store) AllSystemSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM system_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
