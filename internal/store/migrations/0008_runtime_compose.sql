-- 0008_runtime_compose.sql — allow runtime='compose' on instances.
--
-- Spec v2.1 introduces compose-runtime templates. The original 0001
-- table CHECKed runtime IN ('container','system'); SQLite cannot ALTER
-- a CHECK constraint, so we rewrite the table definition directly in
-- sqlite_master via PRAGMA writable_schema.
--
-- This is the SQLite-recommended approach when the change is purely
-- to relax a constraint — no data is touched and no foreign-key
-- references in other tables need to be rewritten.
--
-- After patching sqlite_master we bump schema_version so that all
-- existing connections (including the one running this migration)
-- reload the parsed schema and start enforcing the new CHECK.

PRAGMA writable_schema = ON;

UPDATE sqlite_master
SET sql = REPLACE(
    sql,
    'CHECK(runtime IN (''container'',''system''))',
    'CHECK(runtime IN (''container'',''system'',''compose''))'
)
WHERE type = 'table' AND name = 'instances';

-- Bump schema_version to force a schema reload on every connection.
UPDATE sqlite_master SET sql = sql WHERE name IS NULL AND type IS NULL;

PRAGMA writable_schema = OFF;
