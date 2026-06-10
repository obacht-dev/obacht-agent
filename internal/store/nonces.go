package store

import (
	"context"
	"fmt"
	"time"
)

// nonceRetention is how long seen nonces are kept. Far beyond the signed-
// mutation validity window (minutes) on purpose: pruning too early would
// re-open the replay window for an envelope that is also expired anyway,
// but keeping a day costs nothing and makes the audit trail nicer.
const nonceRetention = 24 * time.Hour

// CheckAndMarkNonce atomically records a signed-mutation nonce. It returns
// fresh=true exactly once per nonce value: the first caller wins, every
// later call (a replay) gets fresh=false. Old entries are pruned
// opportunistically on each call.
func (s *Store) CheckAndMarkNonce(ctx context.Context, nonce string, now time.Time) (bool, error) {
	if nonce == "" {
		return false, fmt.Errorf("empty nonce")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO signed_mutation_nonces(nonce, seen_at) VALUES (?, ?)`,
		nonce, now.Unix())
	if err != nil {
		return false, fmt.Errorf("insert nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	// Prune in the same call; failures are non-fatal (next call retries).
	cutoff := now.Add(-nonceRetention).Unix()
	_, _ = s.db.ExecContext(ctx,
		`DELETE FROM signed_mutation_nonces WHERE seen_at < ?`, cutoff)
	return n == 1, nil
}
