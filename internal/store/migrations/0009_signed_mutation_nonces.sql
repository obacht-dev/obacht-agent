-- Replay protection for user-signed mutations (agent:signed_mutation).
-- One row per accepted-or-attempted nonce; pruned opportunistically on
-- insert (see store/nonces.go). Survives agent restarts by design.
CREATE TABLE IF NOT EXISTS signed_mutation_nonces (
    nonce   TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signed_mutation_nonces_seen_at
    ON signed_mutation_nonces(seen_at);
