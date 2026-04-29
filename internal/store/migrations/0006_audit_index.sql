-- Phase S1: audit log + system settings (foundation for v2 security work).
--
-- audit_log_index is a fast-lookup mirror of the on-disk JSONL audit log
-- at /var/log/obacht/audit.log. The JSONL file is the source of truth
-- (append-only, owned by root:adm); the table exists so obachtctl/IPC can
-- tail without reading the file directly. Both sources share a monotonic
-- `seq` value generated here.
--
-- system_settings is a tiny key/value store used by the agent for runtime
-- toggles such as `power_mode` (S5) and `security_mode` (S2). Values are
-- stringly-typed; consumers parse as needed.

CREATE TABLE IF NOT EXISTS audit_log_index (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             INTEGER NOT NULL,                 -- unix seconds
    op             TEXT    NOT NULL,                 -- e.g. "instance.upsert", "domain.delete"
    actor          TEXT    NOT NULL,                 -- "obachtctl", "reconciler", "template:<id>", "backend"
    target         TEXT,                             -- entity id when applicable (instance id, domain, ...)
    result         TEXT    NOT NULL DEFAULT 'ok',    -- "ok" | "error" | "denied"
    params_hash    TEXT    NOT NULL,                 -- sha256 hex of canonical-JSON params
    params_summary TEXT,                             -- short human-readable summary (no secrets)
    error_message  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log_index(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_op ON audit_log_index(op);

CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO system_settings(key, value, updated_at) VALUES
    ('power_mode',    'false', strftime('%s','now')),
    ('security_mode', 'v1',    strftime('%s','now'));
