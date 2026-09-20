-- intelligence-kernel/migrate_authorities_add_is_root_column.sql
--
-- One-time migration: add authorities.is_root as the ONLY kernel
-- source of truth for root status, replacing the payload.root
-- convention from migrate_mark_genesis_root_authority.sql.
--
-- is_root gates define_authority/grant/revoke/revoke_all and
-- participates in the last-valid-root invariant -- kernel-
-- mechanically-enforced behavior, which per this kernel's own
-- column-vs-payload rule belongs in a column, not opaque payload
-- JSON. Keeping both would be a second, parallel representation of
-- the same fact -- exactly the class of duplication already removed
-- twice this session (supersedes_grant_ids vs revoke receipts;
-- transition()'s new_grants vs grant()). So this migration also
-- strips the now-obsolete "root" key from authority:root's payload,
-- so nothing visually suggests a second mechanism survives.
--
-- Follows SQLite's documented 12-step table-rebuild procedure
-- (same pattern as migrate_receipts_decouple_from_transition.sql):
-- no existing row's authority_id/created_at changes, and every
-- existing payload is preserved byte-for-byte except for the one
-- deliberate key removal on authority:root described above.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_authorities_add_is_root_column.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE authorities_new (
    authority_id    TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    is_root         INTEGER NOT NULL DEFAULT 0 CHECK (is_root IN (0, 1)),
    payload         TEXT NOT NULL DEFAULT '{}'
);

INSERT INTO authorities_new (authority_id, created_at, is_root, payload)
SELECT
    authority_id,
    created_at,
    CASE WHEN json_extract(payload, '$.root') = 1 THEN 1 ELSE 0 END,
    CASE
        WHEN authority_id = 'authority:root'
            THEN json_remove(payload, '$.root')
        ELSE payload
    END
FROM authorities;

DROP TABLE authorities;

ALTER TABLE authorities_new RENAME TO authorities;

CREATE TRIGGER authorities_no_update
BEFORE UPDATE ON authorities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authorities are immutable');
END;

CREATE TRIGGER authorities_no_delete
BEFORE DELETE ON authorities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authorities are append-only');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
