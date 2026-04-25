-- obacht-agent SSOT schema v1
-- This is the single source of truth for what the device "should" be running.
-- The reconcile loop diffs this against observed state (Docker, systemd, Caddy)
-- and converges.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Installed template instances (SSOT).
CREATE TABLE IF NOT EXISTS instances (
    id            TEXT PRIMARY KEY,                              -- instance id (uuid or slug)
    template_id   TEXT NOT NULL,                                 -- e.g. "wordpress", "static-site"
    runtime       TEXT NOT NULL CHECK(runtime IN ('container','system')),
    version       TEXT,                                          -- template version / image tag
    desired_state TEXT NOT NULL CHECK(desired_state IN ('installed','stopped','removed')),
    config_json   TEXT,                                          -- JSON blob (validated against manifest schema)
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- Services exposed by an instance for ingress binding (e.g. "web" → 127.0.0.1:8000).
CREATE TABLE IF NOT EXISTS instance_services (
    instance_id   TEXT NOT NULL,
    service_name  TEXT NOT NULL,                                 -- e.g. "web"
    target_type   TEXT NOT NULL CHECK(target_type IN ('host_port','docker_dns','unix_socket')),
    target        TEXT NOT NULL,                                 -- "127.0.0.1:8000" or "wp_web:80"
    PRIMARY KEY(instance_id, service_name),
    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

-- Domains claimed for this device.
CREATE TABLE IF NOT EXISTS domains (
    domain        TEXT PRIMARY KEY,                              -- example.com
    status        TEXT NOT NULL CHECK(status IN ('pending','claiming','ready','error')),
    cert_state    TEXT,                                          -- json: issuer, not_after, last_error
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- Domain → instance/service routing (ingress).
CREATE TABLE IF NOT EXISTS ingress_bindings (
    domain        TEXT PRIMARY KEY,
    instance_id   TEXT NOT NULL,
    service_name  TEXT NOT NULL,
    mode          TEXT NOT NULL DEFAULT 'root' CHECK(mode IN ('root','path')),
    path_prefix   TEXT,                                          -- only when mode='path'
    FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE,
    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

-- Exclusivity locks (e.g. "display-output" — only one instance can own it).
CREATE TABLE IF NOT EXISTS exclusivity_locks (
    group_name    TEXT PRIMARY KEY,                              -- "display-output"
    instance_id   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

-- Per-instance secret tokens for IPC authentication.
CREATE TABLE IF NOT EXISTS instance_secrets (
    instance_id   TEXT PRIMARY KEY,
    secret        TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

-- Agent metadata (schema version, last reconcile, observed state cache).
CREATE TABLE IF NOT EXISTS agent_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO agent_meta(key, value) VALUES ('schema_version', '1');
