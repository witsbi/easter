-- intelligence-kernel/migrate_receipts_decouple_from_transition.sql
--
-- One-time migration: relax the receipts table's CHECK constraint
-- so an ACCEPTED receipt no longer requires transition_id.
--
-- This is required so a standalone Authority operation (grant,
-- revoke, revoke_all -- see kernel.py) can produce a successful,
-- immutable receipt without fabricating an unrelated State
-- transition just to carry it.
--
-- SQLite cannot ALTER a CHECK constraint in place, so this follows
-- SQLite's documented 12-step table-rebuild procedure. No column is
-- added or removed and no existing row's data changes -- only the
-- constraint on future inserts changes. All 7 pre-migration rows are
-- copied byte-for-byte.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_receipts_decouple_from_transition.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE receipts_new (
    receipt_seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id       TEXT NOT NULL UNIQUE,
    operation_id     TEXT NOT NULL,
    transition_id    TEXT,
    outcome          TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL DEFAULT '{}',

    FOREIGN KEY (transition_id)
        REFERENCES transitions(transition_id),

    CHECK (outcome IN (
        'BOOTSTRAP',
        'ACCEPTED',
        'REJECTED',
        'FAILED'
    )),

    CHECK (
        outcome = 'ACCEPTED'
        OR
        (outcome IN ('BOOTSTRAP', 'REJECTED', 'FAILED') AND transition_id IS NULL)
    )
);

INSERT INTO receipts_new (
    receipt_seq, receipt_id, operation_id, transition_id,
    outcome, created_at, payload
)
SELECT
    receipt_seq, receipt_id, operation_id, transition_id,
    outcome, created_at, payload
FROM receipts;

DROP TABLE receipts;

ALTER TABLE receipts_new RENAME TO receipts;

CREATE INDEX idx_receipts_operation
    ON receipts(operation_id);

CREATE TRIGGER receipts_no_update
BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: receipts are immutable');
END;

CREATE TRIGGER receipts_no_delete
BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: receipts are append-only');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
