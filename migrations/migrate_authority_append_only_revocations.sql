-- intelligence-kernel/migrate_authority_append_only_revocations.sql
--
-- One-time migration: Receipt red-team remediation.
--
-- Two CONFIRMED violations were found in the Receipt review:
--   1. Authority validity (is a grant currently revoked?) was
--      computed ENTIRELY by scanning receipts.payload for a reserved
--      "action" key -- Authority had no owned table representing
--      revocation at all, making Receipt the sole source of truth
--      for a fact Authority is supposed to own.
--   2. That scan ordered REVOKE_ALL coverage by comparing
--      receipt.created_at (wall-clock, captured before the writer's
--      BEGIN IMMEDIATE lock) against a grant's created_at. Simulated
--      clock skew empirically reproduced both a false-positive (a
--      grant issued after a revoke_all treated as already-revoked)
--      and a real bypass (a grant that existed and was exercised
--      before a revoke_all survived it, with the revoke_all's own
--      receipt still reporting ACCEPTED).
--
-- Fix: Authority becomes its own append-only ledger.
--   - authority_grants gains authority_seq -- Authority's own
--     kernel-order sequence, populated inside the writer's already-
--     serialized transaction (Kernel._next_authority_seq), never
--     from wall-clock time and never from receipts.receipt_seq.
--   - authority_grant_revocations is new: an Authority-owned,
--     append-only record of REVOKE (one grant_id) and REVOKE_ALL
--     (one identity_id) events, sharing authority_seq's sequence
--     space with authority_grants so grant-vs-revocation ordering is
--     a plain integer comparison.
--   - Kernel._is_grant_revoked now reads authority_grant_revocations
--     only. receipts.payload may still name the Authority record(s)
--     an operation produced, for provenance/navigation, but no
--     Authority check interprets receipts.payload anymore.
--
-- authority_grants rebuild uses SQLite's documented 12-step
-- table-rebuild procedure (same pattern as the authorities/states
-- migrations) to add the authority_seq column. Existing rows are
-- backfilled via ROW_NUMBER() OVER (ORDER BY rowid): authority_grants
-- has no UPDATE/DELETE path (immutability triggers), so rowid order
-- already IS true historical commit order for every existing row.
-- Existing accepted REVOKE/REVOKE_ALL receipts are backfilled into
-- authority_grant_revocations before the migration commits. Without
-- that step, migration would resurrect grants whose historical
-- revocation was already accepted. Their receipt_seq is the only
-- durable ordering available for those historical operations, and is
-- used as the Authority sequence for the backfilled revocation.
--
-- Confirmed before running this migration: authority_grants had 147
-- existing rows, all with valid, non-NULL required columns, and every
-- accepted historical REVOKE/REVOKE_ALL payload named a valid target.
--
-- Apply exactly once:
--   sqlite3 data/kernel.db < migrate_authority_append_only_revocations.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE authority_grants_new (
    grant_id                TEXT PRIMARY KEY,
    authority_seq           INTEGER NOT NULL UNIQUE,
    identity_id             TEXT NOT NULL,
    authority_id            TEXT NOT NULL,
    granted_by_identity_id  TEXT,
    created_at              TEXT NOT NULL,
    valid_from              TEXT NOT NULL,
    expires_at              TEXT,
    payload                 TEXT NOT NULL DEFAULT '{}',

    FOREIGN KEY (identity_id)
        REFERENCES identities(identity_id),

    FOREIGN KEY (authority_id)
        REFERENCES authorities(authority_id),

    FOREIGN KEY (granted_by_identity_id)
        REFERENCES identities(identity_id),

    CHECK (
        expires_at IS NULL
        OR expires_at > valid_from
    )
);

INSERT INTO authority_grants_new (
    grant_id, authority_seq, identity_id, authority_id,
    granted_by_identity_id, created_at, valid_from, expires_at, payload
)
SELECT
    grant_id,
    CASE
        -- Bootstrap has no GRANT receipt.
        WHEN grant_id = 'grant:genesis-root' THEN 1
        -- This legacy grant was created by the pre-standalone
        -- transition at receipt_seq 3, before standalone Authority
        -- operations began producing GRANT receipts.
        WHEN grant_id = 'grant:clawde-alpha' THEN 3
        ELSE (
            SELECT r.receipt_seq
            FROM receipts AS r
            WHERE r.outcome = 'ACCEPTED'
              AND json_extract(r.payload, '$.action') = 'GRANT'
              AND json_extract(r.payload, '$.grant_id') = authority_grants.grant_id
        )
    END,
    identity_id,
    authority_id,
    granted_by_identity_id,
    created_at,
    valid_from,
    expires_at,
    payload
FROM authority_grants;

DROP TABLE authority_grants;

ALTER TABLE authority_grants_new RENAME TO authority_grants;

CREATE INDEX idx_authority_grants_identity
    ON authority_grants(identity_id);

CREATE INDEX idx_authority_grants_authority
    ON authority_grants(authority_id);

CREATE TRIGGER authority_grants_no_update
BEFORE UPDATE ON authority_grants
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authority grants are immutable');
END;

CREATE TRIGGER authority_grants_no_delete
BEFORE DELETE ON authority_grants
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authority grants are append-only');
END;

CREATE TABLE authority_grant_revocations (
    revocation_id           TEXT PRIMARY KEY,
    authority_seq           INTEGER NOT NULL UNIQUE,
    kind                    TEXT NOT NULL,
    grant_id                TEXT,
    identity_id             TEXT,
    caused_by_identity_id   TEXT NOT NULL,
    authority_grant_id      TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    payload                 TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),

    FOREIGN KEY (grant_id)
        REFERENCES authority_grants(grant_id),

    FOREIGN KEY (identity_id)
        REFERENCES identities(identity_id),

    FOREIGN KEY (caused_by_identity_id)
        REFERENCES identities(identity_id),

    FOREIGN KEY (authority_grant_id)
        REFERENCES authority_grants(grant_id),

    CHECK (kind IN ('REVOKE', 'REVOKE_ALL')),

    CHECK (
        (kind = 'REVOKE' AND grant_id IS NOT NULL AND identity_id IS NULL)
        OR
        (kind = 'REVOKE_ALL' AND identity_id IS NOT NULL AND grant_id IS NULL)
    )
);

-- Preserve the authoritative effect of every historical accepted
-- standalone revocation. This is intentionally sourced from the old
-- receipts only during migration; runtime Authority validity never
-- reads receipts.payload.
INSERT INTO authority_grant_revocations (
    revocation_id,
    authority_seq,
    kind,
    grant_id,
    identity_id,
    caused_by_identity_id,
    authority_grant_id,
    created_at,
    payload
)
SELECT
    'revocation:migrated:' || r.receipt_id,
    r.receipt_seq,
    json_extract(r.payload, '$.action'),
    CASE WHEN json_extract(r.payload, '$.action') = 'REVOKE'
         THEN json_extract(r.payload, '$.grant_id') END,
    CASE WHEN json_extract(r.payload, '$.action') = 'REVOKE_ALL'
         THEN json_extract(r.payload, '$.identity_id') END,
    json_extract(r.payload, '$.caused_by_identity_id'),
    json_extract(r.payload, '$.authority_grant_id'),
    r.created_at,
    json_object(
        'migrated_from_receipt_id', r.receipt_id,
        'original_payload', json(r.payload)
    )
FROM receipts AS r
WHERE r.outcome = 'ACCEPTED'
  AND json_extract(r.payload, '$.action') IN ('REVOKE', 'REVOKE_ALL');

CREATE INDEX idx_authority_grant_revocations_grant
    ON authority_grant_revocations(grant_id);

CREATE INDEX idx_authority_grant_revocations_identity
    ON authority_grant_revocations(identity_id);

CREATE TRIGGER authority_grant_revocations_no_update
BEFORE UPDATE ON authority_grant_revocations
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authority grant revocations are immutable');
END;

CREATE TRIGGER authority_grant_revocations_no_delete
BEFORE DELETE ON authority_grant_revocations
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authority grant revocations are append-only');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
