-- intelligence-kernel/migrate_replace_transition_evidence_with_receipt_evidence.sql
--
-- One-time migration: replace transition_evidence(transition_id,
-- evidence_id) with receipt_evidence(receipt_id, evidence_id).
--
-- Evidence review exposed an abstraction mismatch: Receipts, not
-- Transitions, already represent every kernel operation outcome
-- uniformly (successful Transitions, successful Authority operations,
-- and REJECTED/FAILED attempts of either) -- see receipts' own prior
-- decoupling from transition_id in
-- migrate_receipts_decouple_from_transition.sql. Association of
-- Evidence follows the same split: Evidence supports a Receipt, not
-- specifically a Transition.
--
-- Confirmed before running this migration: both `evidence` and
-- `transition_evidence` have zero rows in the live db (`SELECT
-- COUNT(*) FROM evidence` / `transition_evidence` == 0) -- there is
-- no supported kernel operation that has ever created an Evidence row
-- (record_evidence() is introduced in this same change), so there is
-- no existing association data to carry forward. This migration is
-- therefore a straight structural replacement, not a data rebuild.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_replace_transition_evidence_with_receipt_evidence.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

DROP TABLE IF EXISTS transition_evidence;

CREATE TABLE receipt_evidence (
    receipt_id      TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,

    PRIMARY KEY (receipt_id, evidence_id),

    FOREIGN KEY (receipt_id)
        REFERENCES receipts(receipt_id),

    FOREIGN KEY (evidence_id)
        REFERENCES evidence(evidence_id)
);

CREATE TRIGGER receipt_evidence_no_update
BEFORE UPDATE ON receipt_evidence
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: receipt evidence records are immutable');
END;

CREATE TRIGGER receipt_evidence_no_delete
BEFORE DELETE ON receipt_evidence
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: receipt evidence records are append-only');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
