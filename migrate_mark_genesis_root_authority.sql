-- intelligence-kernel/migrate_mark_genesis_root_authority.sql
--
-- One-time genesis correction: mark authority:root's payload with
-- "root": true.
--
-- The root/capability model (see kernel.py's ROOT / CAPABILITY MODEL
-- section) needs root-ness to live entirely in authorities.payload,
-- checked the same way for every authority -- never a hardcoded
-- authority_id comparison, which would be a second, parallel way to
-- become root and reintroduce exactly the kind of duplicated
-- mechanism this whole redesign has been removing (supersedes_
-- grant_ids vs revoke receipts; transition()'s new_grants vs
-- grant()). authority:root's original genesis definition predates
-- that model and simply never set the key.
--
-- This is data-only (no column/table change) and touches exactly
-- one pre-existing row's payload. authorities is append-only/
-- immutable by trigger, so the trigger is dropped for the duration
-- of this single deliberate correction and recreated immediately
-- after -- the same pattern already used for the receipts CHECK
-- migration. This is a one-time genesis-lineage correction, not a
-- precedent for ordinary kernel code to ever update an authorities
-- row.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_mark_genesis_root_authority.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

DROP TRIGGER authorities_no_update;

UPDATE authorities
SET payload = json_set(payload, '$.root', json('true'))
WHERE authority_id = 'authority:root';

CREATE TRIGGER authorities_no_update
BEFORE UPDATE ON authorities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authorities are immutable');
END;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
