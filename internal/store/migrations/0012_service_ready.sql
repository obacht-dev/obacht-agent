-- Readiness per instance (spec v2.9): a signal separate from observed_state.
-- observed_state=installed still means "the container runs"; service_ready
-- says whether the app behind it answers. Values: '' (not evaluated),
-- 'starting', 'ready', 'unhealthy'. ready_at is set when the instance last
-- became ready (unix seconds), NULL otherwise.
ALTER TABLE instances ADD COLUMN service_ready TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN ready_at INTEGER;
