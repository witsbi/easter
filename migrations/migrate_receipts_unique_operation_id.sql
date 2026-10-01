-- intelligence-kernel/migrate_receipts_unique_operation_id.sql
--
-- One-time migration: enforce one terminal Receipt per operation_id.
--
-- An operation identifier identifies one attempted kernel operation. At most
-- one terminal Receipt may exist for that identifier; when durable outcome
-- recording succeeds, exactly one exists. Supported entry points already
-- minted a fresh operation_id per attempt, but the schema did not enforce the
-- cardinality and record_failure() could append a second terminal outcome.
--
-- Compatibility prerequisite, verified against the historical ledger before
-- this migration was authored:
--
--   SELECT operation_id, COUNT(*)
--   FROM receipts
--   GROUP BY operation_id
--   HAVING COUNT(*) > 1;
--
-- must return no rows. CREATE UNIQUE INDEX is also the transactional fail-
-- closed check. The historical non-unique index is deliberately left in place:
-- if a command-line SQLite client continues after the unique-index statement
-- fails, COMMIT still cannot remove or weaken the existing schema. No receipt
-- row is inserted, updated, deleted, renumbered, or otherwise rewritten.
--
-- Apply exactly once:
--   sqlite3 data/kernel.db < migrations/migrate_receipts_unique_operation_id.sql

BEGIN IMMEDIATE;

CREATE UNIQUE INDEX idx_receipts_operation_unique
    ON receipts(operation_id);

COMMIT;