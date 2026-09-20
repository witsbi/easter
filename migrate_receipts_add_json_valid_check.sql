-- intelligence-kernel/migrate_receipts_add_json_valid_check.sql
--
-- One-time migration: add CHECK(json_valid(payload)) to receipts.
--
-- Part of the Receipt red-team remediation (see
-- migrate_authority_append_only_revocations.sql for the primary
-- fix). Same reasoning already applied to states.payload
-- (migrate_states_add_json_valid_check.sql): valid JSON is a kernel
-- representation invariant, not userland interpretation, so it
-- belongs in SQL structural law, not left as a Python-only guarantee.
-- More load-bearing here than for transitions.payload (still not
-- checked, noted as an accepted hardening gap during the Transition
-- round) because Kernel._is_grant_revoked and other Authority/Receipt
-- code paths parse receipts.payload as JSON; a malformed row (only
-- reachable by bypassing the kernel, same threat model already
-- accepted for the State orphan-graft gap) would previously throw
-- inside json.loads() instead of failing closed with a clear
-- constraint violation.
--
-- Confirmed before running this migration: all 578 existing rows
-- already have valid JSON (`SELECT sum(json_valid(payload)) FROM
-- receipts` == COUNT(*)), so no existing row is affected -- this only
-- changes what future inserts are allowed.
--
-- Follows SQLite's documented 12-step table-rebuild procedure (same
-- pattern as migrate_receipts_decouple_from_transition.sql). No
-- column is added or removed and no existing row's data changes;
-- receipt_seq values are preserved exactly (not renumbered) since
-- receipts.receipt_seq is INTEGER PRIMARY KEY AUTOINCREMENT and other
-- code/tests already depend on specific existing values.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_receipts_add_json_valid_check.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE receipts_new (
    receipt_seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id       TEXT NOT NULL UNIQUE,
    operation_id     TEXT NOT NULL,
    transition_id    TEXT,
    outcome          TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),

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
