-- Add a "local port" alternative to instance/service ingress bindings.
-- When local_port > 0 the binding points at host.docker.internal:<port>,
-- and instance_id/service_name may be NULL. We rebuild the table because
-- SQLite cannot relax the NOT NULL on existing columns in place.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE ingress_bindings_new (
    domain        TEXT PRIMARY KEY,
    instance_id   TEXT,
    service_name  TEXT,
    local_port    INTEGER NOT NULL DEFAULT 0,
    mode          TEXT NOT NULL DEFAULT 'root' CHECK(mode IN ('root','path')),
    path_prefix   TEXT,
    FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE,
    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

INSERT INTO ingress_bindings_new(domain, instance_id, service_name, local_port, mode, path_prefix)
SELECT domain, instance_id, service_name, 0, mode, path_prefix FROM ingress_bindings;

DROP TABLE ingress_bindings;
ALTER TABLE ingress_bindings_new RENAME TO ingress_bindings;
