-- 0004_cert_issuer: track the cert issuer (e.g. "Let's Encrypt R3") so the
-- agent can include it in the observed-state push to the backend without the
-- backend ever holding the private key. SQLite has no IF NOT EXISTS for
-- ALTER TABLE ADD COLUMN; the migration runner is single-shot per file.
ALTER TABLE domains ADD COLUMN cert_issuer TEXT;
