-- Observed state cache (set by reconciler / runtime drivers; consumed by IPC + WS push).

ALTER TABLE instances ADD COLUMN observed_state TEXT;
ALTER TABLE instances ADD COLUMN observed_at    INTEGER;
ALTER TABLE instances ADD COLUMN observed_json  TEXT;

UPDATE agent_meta SET value = '2' WHERE key = 'schema_version';
