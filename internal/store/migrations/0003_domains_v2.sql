-- Phase 3: ingress / domain state machine.
-- The schema-v1 `domains.status` column conflates desired vs observed.
-- v2 splits them so the agent can record claim/cert progress without losing
-- the user-requested target.

ALTER TABLE domains ADD COLUMN desired_status   TEXT;
ALTER TABLE domains ADD COLUMN observed_status  TEXT;
ALTER TABLE domains ADD COLUMN cert_not_after   INTEGER;
ALTER TABLE domains ADD COLUMN last_error       TEXT;

-- Backfill from the legacy `status` field so existing rows keep working.
UPDATE domains SET desired_status  = COALESCE(desired_status,  status);
UPDATE domains SET observed_status = COALESCE(observed_status, status);

UPDATE agent_meta SET value = '3' WHERE key = 'schema_version';
