-- Per-domain HTTP Basic Auth. The webapp/apps send username+password via a
-- signed mutation (domain.set_basic_auth); the agent bcrypt-hashes the
-- password and stores ONLY the hash here. Credentials never leave the
-- device: observed-state snapshots echo the username (so the UI can show
-- "protected"), never the hash.
ALTER TABLE domains ADD COLUMN basic_auth_user TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN basic_auth_hash TEXT NOT NULL DEFAULT '';
