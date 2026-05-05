-- 0007_template_secrets.sql — per-instance, per-key template secrets.
--
-- Used by the compose runtime to materialise ${secret.<key>} placeholders.
-- Secrets are auto-generated on first install with crypto/rand and never
-- leave the device. The api/registry never see them.
--
-- Distinct from instance_secrets (which holds a single bearer token used
-- for the agent IPC by templates that opt in).
CREATE TABLE IF NOT EXISTS template_secrets (
  instance_id TEXT NOT NULL,
  secret_key  TEXT NOT NULL,
  secret_val  TEXT NOT NULL,
  charset     TEXT NOT NULL DEFAULT 'alphanumeric',
  length      INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (instance_id, secret_key)
);
