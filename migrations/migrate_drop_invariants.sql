-- intelligence-kernel/migrate_drop_invariants.sql
--
-- One-time migration: drop the obsolete Invariant stored primitive
-- (`invariants`, `transition_invariants`) entirely.
--
-- Invariant red-team review established: `invariants` had no supported
-- creation path anywhere in kernel.py, `InvariantError` was defined but
-- never raised, no evaluator existed, and no kernel operation ever
-- executed an Invariant. `transition_invariants` recorded citation
-- only, and its FOREIGN KEY into `invariants` made ANY non-empty
-- invariant_ids argument to transition() structurally guaranteed to
-- fail (no invariant could ever exist to cite). Nathan's decision: the
-- concept of a kernel invariant remains as architectural terminology
-- for a structural law the kernel enforces through its own mechanics
-- (schema CHECK/UNIQUE/FK constraints, triggers, Python admission
-- logic) -- not as a user-definable stored primitive. See
-- kernel.py's transition() (invariant_ids parameter removed in the
-- same change) and the Invariant red-team review deliverable.
--
-- Confirmed before running this migration: both `invariants` and
-- `transition_invariants` have zero rows in the live db (`SELECT
-- COUNT(*) FROM invariants` / `transition_invariants` == 0) -- no
-- invariant has ever existed, and no transition has ever successfully
-- cited one (structurally impossible, see above). This migration
-- therefore destroys no authoritative historical data.
--
-- Apply exactly once: sqlite3 data/kernel.db < migrate_drop_invariants.sql

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

DROP TABLE IF EXISTS transition_invariants;
DROP TABLE IF EXISTS invariants;

PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
