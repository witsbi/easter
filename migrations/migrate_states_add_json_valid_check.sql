-- intelligence-kernel/migrate_states_add_json_valid_check.sql
--
-- One-time migration: add CHECK(json_valid(payload)) to states.
--
-- Valid JSON is a kernel representation invariant, not userland
-- interpretation, so per the same column-vs-payload reasoning that
-- put is_root on authorities, this belongs in SQL structural law
-- (design principle 3), not left as a Python-only guarantee
-- (encode_payload always produces valid JSON already, but that gave
-- no defense against a direct-SQL boundary violation writing
-- something else). Confirmed before running this migration: all 60
-- existing rows already have valid JSON (`SELECT sum(json_valid(
-- payload)) FROM states` == COUNT(*)), so no existing row is
-- affected -- this only changes what future inserts are allowed.
--
-- Follows SQLite's documented 12-step table-rebuild procedure (same
-- pattern as the receipts/authorities migrations). No column is
-- added or removed and no existing row's data changes.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_states_add_json_valid_check.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE states_new (
    state_id         TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL CHECK (json_valid(payload))
);

INSERT INTO states_new (state_id, created_at, payload)
SELECT state_id, created_at, payload
FROM states;

DROP TABLE states;

ALTER TABLE states_new RENAME TO states;

CREATE TRIGGER states_no_update
BEFORE UPDATE ON states
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: states are immutable');
END;

CREATE TRIGGER states_no_delete
BEFORE DELETE ON states
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: states are append-only');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
