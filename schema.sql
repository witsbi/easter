-- intelligence-kernel/schema.sql
--
-- Intelligence Kernel v0.1
-- Candidate authoritative storage schema.
--
-- Design principles:
--   1. Authoritative records are append-only.
--   2. Committed records are immutable.
--   3. SQLite enforces structural kernel laws.
--   4. Python enforces semantic kernel laws.
--   5. Userland meaning lives in JSON payloads, not schema.
--   6. Proposed/rejected transitions never become authoritative transitions.
--   7. Failed operations leave immutable receipts/exceptions.
--   8. No UPDATE or DELETE of authoritative records.

PRAGMA foreign_keys = ON;


-- ============================================================
-- IDENTITY
-- ============================================================
--
-- An identity is a stable kernel-recognized actor.
-- The kernel does not assign application meaning to the identity.
--
-- Examples might eventually include a human, agent, service, or
-- other actor, but those distinctions belong in payload/userland.
-- ============================================================

CREATE TABLE identities (
    identity_id     TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    payload         TEXT NOT NULL DEFAULT '{}'
);


-- ============================================================
-- AUTHORITY
-- ============================================================
--
-- Defines an authority that can be granted to an identity.
--
-- Authority definition and authority possession are intentionally
-- separate concepts.
--
-- is_root is a kernel-mechanically-enforced property, not opaque
-- userland meaning: it gates define_authority/grant/revoke/
-- revoke_all and participates in the last-valid-root invariant (see
-- kernel.py). That is exactly the "columns exist for properties the
-- kernel must mechanically enforce" rule, so it is a column, not a
-- reserved payload key. It is the ONLY kernel source of truth for
-- root status -- there is no fallback to payload, by design.
-- ============================================================

CREATE TABLE authorities (
    authority_id    TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    is_root         INTEGER NOT NULL DEFAULT 0 CHECK (is_root IN (0, 1)),
    payload         TEXT NOT NULL DEFAULT '{}'
);


-- ============================================================
-- AUTHORITY GRANTS
-- ============================================================
--
-- Immutable evidence that an authority was granted to an identity.
--
-- granted_by identifies the identity exercising authority to make
-- the grant. Genesis/bootstrap behavior will need explicit kernel
-- handling.
--
-- Revocation/supersession is NOT represented by mutating this row.
-- A later authoritative record must represent that change.

CREATE TABLE authority_grants (
    grant_id                TEXT PRIMARY KEY,
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

-- ============================================================
-- STATES
-- ============================================================
--
-- An immutable committed state.
--
-- Lineage is represented exclusively by transitions.from_state_id ->
-- transitions.to_state_id, never by a column on this table --
-- states.parent_state_id was deliberately removed. Genesis
-- (state:genesis, seeded by genesis_seed.sql) is the one state with
-- no incoming transition; it is identified by that literal ID, not
-- by any structural marker on this table.
--
-- Duplicate/replayed transition() calls from the same from_state_id
-- are not deduplicated here or anywhere else: each accepted call
-- commits its own distinct state and is a valid separate branch.
-- The kernel has no canonical-head/current-state concept and does
-- not merge branches -- which branch to continue from is entirely a
-- userland choice, made per call, forever.
--
-- State meaning belongs entirely to payload. Being valid JSON is a
-- kernel representation invariant, not interpretation of userland
-- meaning -- enforced structurally here via json_valid(), the same
-- split already used for is_root (mechanically-enforced properties
-- get SQL, not just Python, enforcement). This is a backstop against
-- direct-SQL boundary violations; encode_payload already guarantees
-- valid JSON for every write that goes through the kernel.
-- ============================================================

CREATE TABLE states (
    state_id         TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL CHECK (json_valid(payload))
);


-- ============================================================
-- INVARIANTS
-- ============================================================
--
-- Immutable definitions/references for kernel-recognized
-- invariants.
--
-- SQLite stores them. Python evaluates them.
-- ============================================================

CREATE TABLE invariants (
    invariant_id     TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL
);


-- ============================================================
-- EVIDENCE
-- ============================================================
--
-- Immutable evidence available to support an authoritative
-- operation.
--
-- Evidence content/meaning is opaque to SQLite.
-- ============================================================

CREATE TABLE evidence (
    evidence_id      TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL
);


-- ============================================================
-- TRANSITIONS
-- ============================================================
--
-- A row exists here ONLY for a committed authoritative transition.
--
-- Failed or rejected proposals MUST NOT be inserted here.
--
-- authority_grant_id records the actual grant exercised for this
-- transition rather than merely storing an authority label.
-- ============================================================

CREATE TABLE transitions (
    transition_id       TEXT PRIMARY KEY,
    from_state_id       TEXT NOT NULL,
    to_state_id         TEXT NOT NULL,
    authority_grant_id  TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    payload             TEXT NOT NULL DEFAULT '{}',

    FOREIGN KEY (from_state_id)
        REFERENCES states(state_id),

    FOREIGN KEY (to_state_id)
        REFERENCES states(state_id),

    FOREIGN KEY (authority_grant_id)
        REFERENCES authority_grants(grant_id),

    CHECK (from_state_id <> to_state_id),

    UNIQUE (to_state_id)
);


-- ============================================================
-- TRANSITION INVARIANTS
-- ============================================================
--
-- Records which invariants participated in validating a committed
-- transition.
-- ============================================================

CREATE TABLE transition_invariants (
    transition_id   TEXT NOT NULL,
    invariant_id    TEXT NOT NULL,

    PRIMARY KEY (transition_id, invariant_id),

    FOREIGN KEY (transition_id)
        REFERENCES transitions(transition_id),

    FOREIGN KEY (invariant_id)
        REFERENCES invariants(invariant_id)
);


-- ============================================================
-- TRANSITION EVIDENCE
-- ============================================================
--
-- Records evidence associated with a committed transition.
-- ============================================================

CREATE TABLE transition_evidence (
    transition_id   TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,

    PRIMARY KEY (transition_id, evidence_id),

    FOREIGN KEY (transition_id)
        REFERENCES transitions(transition_id),

    FOREIGN KEY (evidence_id)
        REFERENCES evidence(evidence_id)
);


-- ============================================================
-- RECEIPTS
-- ============================================================
--
-- Immutable receipt for a kernel operation.
--
-- A receipt may reference a committed transition, but does not
-- have to -- an ACCEPTED Authority operation (grant/revoke/
-- revoke_all) has no transition at all, and is described entirely
-- by its own opaque payload, the same way transitions already
-- describe supersession-like facts in their own payload. Failed
-- operations never have an authoritative transition.
--
-- operation_id lets the receipt refer to the attempted operation
-- without pretending that attempt became authoritative state.
-- ============================================================

CREATE TABLE receipts (
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


-- ============================================================
-- EXCEPTIONS
-- ============================================================
--
-- Immutable record describing why an operation failed.
--
-- Exceptions are receipts/evidence of failure, not mutations of
-- authoritative state.
-- ============================================================

CREATE TABLE exceptions (
    exception_id     TEXT PRIMARY KEY,
    receipt_id       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    payload          TEXT NOT NULL,

    FOREIGN KEY (receipt_id)
        REFERENCES receipts(receipt_id),

    UNIQUE (receipt_id)
);


-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX idx_authority_grants_identity
    ON authority_grants(identity_id);

CREATE INDEX idx_authority_grants_authority
    ON authority_grants(authority_id);

CREATE INDEX idx_transitions_from_state
    ON transitions(from_state_id);

CREATE INDEX idx_transitions_authority_grant
    ON transitions(authority_grant_id);

CREATE INDEX idx_receipts_operation
    ON receipts(operation_id);


-- ============================================================
-- IMMUTABILITY TRIGGERS
-- ============================================================
--
-- Kernel law:
--
--     Once authoritative data is committed,
--     it cannot be rewritten or deleted.
--
-- Corrections and recovery happen through new records.
-- ============================================================


-- identities

CREATE TRIGGER identities_no_update
BEFORE UPDATE ON identities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: identities are immutable');
END;

CREATE TRIGGER identities_no_delete
BEFORE DELETE ON identities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: identities are append-only');
END;


-- authorities

CREATE TRIGGER authorities_no_update
BEFORE UPDATE ON authorities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authorities are immutable');
END;

CREATE TRIGGER authorities_no_delete
BEFORE DELETE ON authorities
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: authorities are append-only');
END;


-- authority_grants

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


-- states

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


-- invariants

CREATE TRIGGER invariants_no_update
BEFORE UPDATE ON invariants
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: invariants are immutable');
END;

CREATE TRIGGER invariants_no_delete
BEFORE DELETE ON invariants
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: invariants are append-only');
END;


-- evidence

CREATE TRIGGER evidence_no_update
BEFORE UPDATE ON evidence
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: evidence is immutable');
END;

CREATE TRIGGER evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: evidence is append-only');
END;


-- transitions

CREATE TRIGGER transitions_no_update
BEFORE UPDATE ON transitions
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: transitions are immutable');
END;

CREATE TRIGGER transitions_no_delete
BEFORE DELETE ON transitions
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: transitions are append-only');
END;


-- transition_invariants

CREATE TRIGGER transition_invariants_no_update
BEFORE UPDATE ON transition_invariants
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: transition invariant records are immutable');
END;

CREATE TRIGGER transition_invariants_no_delete
BEFORE DELETE ON transition_invariants
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: transition invariant records are append-only');
END;


-- transition_evidence

CREATE TRIGGER transition_evidence_no_update
BEFORE UPDATE ON transition_evidence
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: transition evidence records are immutable');
END;

CREATE TRIGGER transition_evidence_no_delete
BEFORE DELETE ON transition_evidence
BEGIN
    SELECT RAISE(ABORT,
        'kernel violation: transition evidence records are append-only');
END;


-- receipts

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


-- exceptions

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
