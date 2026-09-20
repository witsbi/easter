-- intelligence-kernel/migrate_exceptions_add_json_valid_check.sql
--
-- One-time migration: add CHECK(json_valid(payload)) to exceptions.
--
-- Part of Receipt final cleanup (see the FAILED-Receipt-minimality
-- fix in kernel.py's record_failure(), which stops copying `details`
-- into the Receipt payload -- Exception is now unambiguously the
-- sole owner of diagnostic detail). Same reasoning already applied to
-- receipts.payload (migrate_receipts_add_json_valid_check.sql) and
-- states.payload: valid JSON is a kernel representation invariant,
-- not userland interpretation, so it belongs in SQL structural law,
-- not left as a Python-only guarantee. This adds no semantic
-- interpretation of Exception content -- structural validity only.
--
-- Confirmed before running this migration: all 291 existing rows
-- already have valid JSON (`SELECT COUNT(*), SUM(json_valid(payload))
-- FROM exceptions` == 291/291), so no existing row is affected --
-- this only changes what future inserts are allowed.
--
-- Follows SQLite's documented 12-step table-rebuild procedure (same
-- pattern as migrate_receipts_add_json_valid_check.sql). No column is
-- added or removed and no existing row's data changes.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_exceptions_add_json_valid_check.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE exceptions_new (
    exception_id     TEXT PRIMARY KEY,
    receipt_id       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL CHECK (json_valid(payload)),

    FOREIGN KEY (receipt_id)
        REFERENCES receipts(receipt_id),

    UNIQUE (receipt_id)
);

INSERT INTO exceptions_new (
    exception_id, receipt_id, created_at, payload
)
SELECT
    exception_id, receipt_id, created_at, payload
FROM exceptions;

DROP TABLE exceptions;

ALTER TABLE exceptions_new RENAME TO exceptions;

CREATE TRIGGER exceptions_no_update
BEFORE UPDATE ON exceptions
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: exceptions are immutable');
END;

CREATE TRIGGER exceptions_no_delete
BEFORE DELETE ON exceptions
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: exceptions are append-only');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
