-- intelligence-kernel/genesis_seed.sql
--
-- Intelligence Kernel v0.1
-- Genesis bootstrap seed.
--
-- This file creates the initial authoritative root from which
-- subsequent authority and state transitions can derive.
--
-- IMPORTANT:
--   Genesis is exceptional by definition.
--   The root authority grant has no prior granting identity.
--   Normal kernel operations MUST NOT permit this behavior.
--
-- This seed should be applied exactly once to an empty database.


PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;


-- ============================================================
-- GENESIS IDENTITY
-- ============================================================
--
-- Establish the initial identity.
--
-- The kernel itself does not interpret "human", "Nathan", etc.
-- Those are userland assertions carried in the payload.
-- ============================================================

INSERT INTO identities (
    identity_id,
    created_at,
    payload
)
VALUES (
    'identity:nathan',
    '2026-09-19T00:00:00Z',
    json_object(
        'name', 'Nathan',
        'role', 'genesis_identity'
    )
);


-- ============================================================
-- ROOT AUTHORITY
-- ============================================================
--
-- Establish the authority from which subsequent authority can
-- descend.
-- ============================================================

INSERT INTO authorities (
    authority_id,
    created_at,
    payload
)
VALUES (
    'authority:root',
    '2026-09-19T00:00:00Z',
    json_object(
        'name', 'root',
        'description', 'Genesis root authority'
    )
);


-- ============================================================
-- GENESIS AUTHORITY GRANT
-- ============================================================
--
-- This is the single bootstrap exception.
--
-- granted_by_identity_id is NULL because no prior authoritative
-- identity/grant exists from which genesis could derive.
--
-- Python must later prevent ordinary operations from creating
-- equivalent unparented authority grants.
-- ============================================================

INSERT INTO authority_grants (
    grant_id,
    identity_id,
    authority_id,
    granted_by_identity_id,
    created_at,
    valid_from,
    expires_at,
    payload
)
VALUES (
    'grant:genesis-root',
    'identity:nathan',
    'authority:root',
    NULL,
    '2026-09-19T00:00:00Z',
    '2026-09-19T00:00:00Z',
    NULL,
    json_object(
        'genesis', 1,
        'reason', 'Initial root authority bootstrap'
    )
);

-- ============================================================
-- GENESIS STATE
-- ============================================================
--
-- Genesis has no parent and no incoming transition.
-- ============================================================

INSERT INTO states (
    state_id,
    created_at,
    payload
)
VALUES (
    'state:genesis',
    '2026-09-19T00:00:00Z',
    json_object(
        'genesis', 1,
        'version', '0.1'
    )
);

-- ============================================================
-- GENESIS RECEIPT
-- ============================================================
--
-- Records the exceptional bootstrap operation.
--
-- Genesis has no incoming transition, so transition_id is NULL.
-- BOOTSTRAP is reserved for this exceptional root operation.
-- ============================================================

INSERT INTO receipts (
    receipt_id,
    operation_id,
    transition_id,
    outcome,
    created_at,
    payload
)
VALUES (
    'receipt:genesis',
    'operation:genesis',
    NULL,
    'BOOTSTRAP',
    '2026-09-19T00:00:00Z',
    json_object(
        'genesis', 1,
        'description', 'Intelligence Kernel v0.1 genesis bootstrap'
    )
);


COMMIT; 
