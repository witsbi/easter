#!/usr/bin/env python3
"""
Intelligence Kernel v0.1

Reference Python implementation.

Responsibilities:
    - Own all writes to authoritative SQLite state.
    - Validate authority before committing transitions.
    - Preserve append-only semantics.
    - Commit state + transition + evidence links + invariant links
      + receipt atomically.
    - Produce failure receipts/exceptions without changing state.

SQLite remains responsible for:
    - Foreign-key integrity
    - Structural constraints
    - Immutability triggers
    - Transaction atomicity

Userland must not write the database directly.
"""

from __future__ import annotations

import json
import sqlite3
import uuid

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


DEFAULT_DB = Path(__file__).parent / "data" / "kernel.db"


class KernelError(Exception):
    """Base exception for kernel failures."""


class AuthorityError(KernelError):
    """Raised when authority validation fails."""


class StateError(KernelError):
    """Raised when state validation fails."""


class InvariantError(KernelError):
    """Raised when an invariant fails."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}:{uuid.uuid4()}"


def encode_payload(payload: dict[str, Any] | None) -> str:
    return json.dumps(
        payload or {},
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Kernel:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = Path(db_path)

        if not self.db_path.exists():
            raise FileNotFoundError(
                f"Kernel database does not exist: {self.db_path}"
            )

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # Foreign-key enforcement is connection-specific in SQLite.
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA recursive_triggers = ON")


        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()

        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

    # ---------------------------------------------------------
    # READS
    # ---------------------------------------------------------

    def get_state(self, state_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    state_id,
                    created_at,
                    payload
                FROM states
                WHERE state_id = ?
                """,
                (state_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "state_id": row["state_id"],
            "created_at": row["created_at"],
            "payload": json.loads(row["payload"]),
        }

    def get_genesis_state(self) -> dict[str, Any] | None:
        return self.get_state("state:genesis")

    def get_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    receipt_id,
                    operation_id,
                    transition_id,
                    outcome,
                    created_at,
                    payload
                FROM receipts
                WHERE receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "receipt_id": row["receipt_id"],
            "operation_id": row["operation_id"],
            "transition_id": row["transition_id"],
            "outcome": row["outcome"],
            "created_at": row["created_at"],
            "payload": json.loads(row["payload"]),
        }

    def count_states(self) -> int:
        with self.connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) AS n FROM states"
            ).fetchone()["n"]

    def count_transitions(self) -> int:
        with self.connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) AS n FROM transitions"
            ).fetchone()["n"]

    def _get_grant(
        self, conn: sqlite3.Connection, grant_id: str
    ) -> dict[str, Any] | None:
        row = conn.execute(
            """
            SELECT
                grant_id,
                identity_id,
                authority_id,
                granted_by_identity_id,
                created_at,
                valid_from,
                expires_at,
                payload
            FROM authority_grants
            WHERE grant_id = ?
            """,
            (grant_id,),
        ).fetchone()

        if row is None:
            return None

        return {
            "grant_id": row["grant_id"],
            "identity_id": row["identity_id"],
            "authority_id": row["authority_id"],
            "granted_by_identity_id": row["granted_by_identity_id"],
            "created_at": row["created_at"],
            "valid_from": row["valid_from"],
            "expires_at": row["expires_at"],
            "payload": json.loads(row["payload"]),
        }

    def get_grant(self, grant_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            return self._get_grant(conn, grant_id)

    # ---------------------------------------------------------
    # AUTHORITY
    # ---------------------------------------------------------
    #
    # _get_grant/_is_grant_revoked/_validate_grant all take an
    # explicit conn rather than opening their own connection. This
    # lets an authoritative operation (transition/grant/revoke/
    # revoke_all) call _validate_grant using the *same* connection
    # that is holding its BEGIN IMMEDIATE write lock, so authority
    # validation is evaluated as part of the same serialized
    # transaction that commits the operation -- never against a
    # separate, earlier, unlocked read. See validate_grant's
    # docstring for why that earlier read was a real gap.
    #
    # The plain get_grant/is_grant_revoked/validate_grant methods
    # above/below remain for read-only inspection (tests, evidence,
    # CLI) where no write transaction is being held.

    def _is_grant_revoked(
        self, conn: sqlite3.Connection, grant_id: str
    ) -> bool:
        """
        Whether a standalone Authority REVOKE or REVOKE_ALL operation
        (see revoke/revoke_all below) has invalidated this grant.

        This uses no schema beyond the existing receipts table.
        receipts.payload is already opaque, kernel-agnostic JSON
        (design principle 5: "userland meaning lives in JSON
        payloads, not schema"). An ACCEPTED receipt may carry a
        reserved "action" key of "REVOKE" or "REVOKE_ALL"; this is a
        Python-side *semantic* law (design principle 4), not a
        structural one, so it is evaluated here rather than in
        SQLite. Only ACCEPTED receipts are considered -- a rejected
        or failed revoke attempt never counts.

        REVOKE names one grant_id directly: permanent, unconditional.

        REVOKE_ALL names one identity_id: every grant that identity
        held as of that receipt's created_at becomes invalid. A
        grant created AFTER that receipt for the same identity is
        unaffected -- REVOKE_ALL revokes what existed at that moment,
        it does not ban the identity going forward.

        This replaces the removed is_grant_superseded/
        supersedes_grant_ids mechanism, which coupled revocation to
        State transitions. Revocation is now independent of State
        entirely, evaluated purely against wall-clock receipt
        history -- never against State lineage or which branch/State
        an operation is being attempted from.
        """

        grant = self._get_grant(conn, grant_id)

        if grant is None:
            return False

        grant_created_at = parse_timestamp(grant["created_at"])

        rows = conn.execute(
            """
            SELECT created_at, payload
            FROM receipts
            WHERE outcome = 'ACCEPTED'
            """
        ).fetchall()

        for row in rows:
            payload = json.loads(row["payload"])
            action = payload.get("action")

            if action == "REVOKE" and payload.get("grant_id") == grant_id:
                return True

            if (
                action == "REVOKE_ALL"
                and payload.get("identity_id") == grant["identity_id"]
                and grant_created_at <= parse_timestamp(row["created_at"])
            ):
                return True

        return False

    def is_grant_revoked(self, grant_id: str) -> bool:
        with self.connect() as conn:
            return self._is_grant_revoked(conn, grant_id)

    def _validate_grant(
        self,
        conn: sqlite3.Connection,
        grant_id: str,
        at_time: str | None = None,
        requester_identity_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate that a grant exists, is temporally valid, has not
        been revoked, and (when a requester is given) is actually
        held by the identity attempting to exercise it -- using conn,
        the caller's own write-transaction connection.

        v0.1 currently validates:
            - grant exists
            - valid_from has been reached
            - expires_at has not been reached
            - grant has not been revoked (see _is_grant_revoked)
            - the requesting identity is the identity the grant was
              issued to, when a requester is supplied

        Callers that consume this grant to authorize a write
        (transition/grant/revoke/revoke_all) MUST call this from
        inside their own `with self.transaction() as conn:` block,
        passing that same conn, and MUST do so before any other read
        that the operation's outcome depends on. `self.transaction()`
        issues `BEGIN IMMEDIATE` on entry, which takes SQLite's
        write lock immediately -- so a validation read taken after
        that point is guaranteed to see every previously *committed*
        fact, and no concurrent writer can commit a contradicting
        fact (e.g. a revoke) while this transaction is still open.
        Validating on a separate, earlier, unlocked connection (the
        original v0.1 design) cannot make that guarantee: a revoke
        could commit in the gap between that read and this
        transaction's BEGIN IMMEDIATE, and the operation would
        commit having validated against authority that was already
        stale by the time it actually took effect.
        """

        grant = self._get_grant(conn, grant_id)

        if grant is None:
            raise AuthorityError(
                f"authority grant does not exist: {grant_id}"
            )

        if (
            requester_identity_id is not None
            and grant["identity_id"] != requester_identity_id
        ):
            raise AuthorityError(
                f"identity {requester_identity_id} does not hold "
                f"grant: {grant_id}"
            )

        now = parse_timestamp(at_time or utc_now())
        valid_from = parse_timestamp(grant["valid_from"])

        if now < valid_from:
            raise AuthorityError(
                f"authority grant is not yet valid: {grant_id}"
            )

        expires_at = grant["expires_at"]

        if expires_at is not None:
            expiration = parse_timestamp(expires_at)

            if now >= expiration:
                raise AuthorityError(
                    f"authority grant has expired: {grant_id}"
                )

        if self._is_grant_revoked(conn, grant_id):
            raise AuthorityError(
                f"authority grant has been revoked: {grant_id}"
            )

        return grant

    def validate_grant(
        self,
        grant_id: str,
        at_time: str | None = None,
        requester_identity_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Read-only validity check outside of any write transaction --
        for inspection/evidence/tests only. An authoritative operation
        that commits a write based on this grant must use
        _validate_grant from inside its own write transaction instead
        (see that docstring for why this one is not safe for that).
        """

        with self.connect() as conn:
            return self._validate_grant(
                conn,
                grant_id,
                at_time=at_time,
                requester_identity_id=requester_identity_id,
            )

    # ---------------------------------------------------------
    # ROOT / CAPABILITY MODEL
    # ---------------------------------------------------------
    #
    # authorities.is_root is the ONLY kernel source of truth for root
    # status -- a real column, not a reserved payload key. Root
    # status is kernel-mechanically-enforced (it gates define_
    # authority/grant/revoke/revoke_all and participates in the
    # last-valid-root invariant below), which is exactly the
    # "columns exist for properties the kernel must mechanically
    # enforce; JSON carries opaque/userland meaning" rule this schema
    # already follows for everything else. An earlier version of
    # this checked payload.root instead; that was deliberately
    # replaced, not kept as a fallback -- there is no code path
    # anywhere in this kernel that reads payload looking for "root".
    # A malformed or misleading authorities.payload (including one
    # that literally contains {"root": true}) cannot affect root
    # status; only is_root can.
    #
    # A grant "is root" iff it references a root authority
    # definition. Root-ness is a property of the authority
    # definition, not of the grant, matching the schema's own stated
    # split ("authority definition and possession are intentionally
    # separate concepts") -- multiple grants (to multiple identities)
    # can all be root by referencing the same root authority, or a
    # second root authority defined via define_authority, with no
    # additional mechanism.
    #
    # grant()/revoke()/revoke_all()/define_authority() all require a
    # root grant. This is what makes non-amplification free: since a
    # non-root identity can never reach any of those four methods,
    # there is no capability set for it to exceed. transition() is
    # deliberately excluded from this gate and remains open to any
    # currently-valid grant, root or not -- but, as of this design,
    # transition() can no longer create or mutate Authority at all
    # (no new_grants/new_authorities), so an unrestricted requester
    # cannot use it to manufacture authority either.
    #
    # v0.1 boundary, deliberately not addressed here: any currently
    # valid non-root grant authorizes ordinary State transitions.
    # authority_id does not provide fine-grained State-transition
    # scope in Kernel v0.1 -- root grants additionally authorize
    # Authority administration, but no grant, root or not, is scoped
    # to a subset of possible transitions. No RBAC/capability
    # hierarchy is being built for this; it is an accepted, open
    # boundary of this version, tracked separately from Authority.

    def _authority_is_root(
        self, conn: sqlite3.Connection, authority_id: str
    ) -> bool:
        row = conn.execute(
            "SELECT is_root FROM authorities WHERE authority_id = ?",
            (authority_id,),
        ).fetchone()

        if row is None:
            return False

        return row["is_root"] == 1

    def _grant_is_root(
        self, conn: sqlite3.Connection, grant: dict[str, Any]
    ) -> bool:
        return self._authority_is_root(conn, grant["authority_id"])

    def _validate_root_grant(
        self,
        conn: sqlite3.Connection,
        grant_id: str,
        requester_identity_id: str,
    ) -> dict[str, Any]:
        """
        Validate grant_id exactly as _validate_grant does, and
        additionally require it to be root. Used by every Authority
        operation that must not be reachable by a non-root identity:
        grant, revoke, revoke_all, define_authority.
        """

        grant = self._validate_grant(
            conn,
            grant_id,
            requester_identity_id=requester_identity_id,
        )

        if not self._grant_is_root(conn, grant):
            raise AuthorityError(
                f"authority grant does not hold root authority, "
                f"required for this Authority operation: {grant_id}"
            )

        return grant

    def _count_other_valid_root_grants(
        self,
        conn: sqlite3.Connection,
        excluding_grant_ids: set[str],
    ) -> int:
        """
        How many currently-valid (unrevoked) root grants exist, other
        than the ones in excluding_grant_ids. Used by revoke/
        revoke_all to enforce that no accepted Authority operation
        may leave the kernel with zero currently-valid root grants --
        evaluated inside the same serialized write transaction as
        the operation itself, using the same conn, so a concurrent
        second revoke cannot race around this check either.
        """

        root_authority_ids = {
            row["authority_id"]
            for row in conn.execute(
                "SELECT authority_id FROM authorities WHERE is_root = 1"
            ).fetchall()
        }

        if not root_authority_ids:
            return 0

        placeholders = ",".join("?" for _ in root_authority_ids)
        rows = conn.execute(
            f"""
            SELECT grant_id
            FROM authority_grants
            WHERE authority_id IN ({placeholders})
            """,
            tuple(root_authority_ids),
        ).fetchall()

        count = 0
        for row in rows:
            grant_id = row["grant_id"]
            if grant_id in excluding_grant_ids:
                continue
            if not self._is_grant_revoked(conn, grant_id):
                count += 1

        return count

    # ---------------------------------------------------------
    # FAILURE RECEIPTS
    # ---------------------------------------------------------

    def record_failure(
        self,
        *,
        operation_id: str,
        outcome: str,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        """
        Record a failed/rejected kernel operation.

        This creates no state and no authoritative transition.
        """

        if outcome not in {"REJECTED", "FAILED"}:
            raise ValueError(
                "failure receipt outcome must be REJECTED or FAILED"
            )

        receipt_id = new_id("receipt")
        exception_id = new_id("exception")
        created_at = utc_now()

        receipt_payload = {
            "reason": reason,
        }

        if details:
            receipt_payload["details"] = details

        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO receipts (
                    receipt_id,
                    operation_id,
                    transition_id,
                    outcome,
                    created_at,
                    payload
                )
                VALUES (?, ?, NULL, ?, ?, ?)
                """,
                (
                    receipt_id,
                    operation_id,
                    outcome,
                    created_at,
                    encode_payload(receipt_payload),
                ),
            )

            conn.execute(
                """
                INSERT INTO exceptions (
                    exception_id,
                    receipt_id,
                    created_at,
                    payload
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    exception_id,
                    receipt_id,
                    created_at,
                    encode_payload(
                        {
                            "reason": reason,
                            "details": details or {},
                        }
                    ),
                ),
            )

        return receipt_id

    # ---------------------------------------------------------
    # AUTHORITY OPERATIONS
    # ---------------------------------------------------------
    #
    # Grant, revoke, and revoke_all are kernel Authority operations
    # in their own right. None of them require or produce a State
    # transition -- Authority is an independent lifecycle from State.
    #
    # Each writes into existing tables only (authority_grants,
    # receipts) and follows the same atomicity/failure-receipt
    # pattern as transition() below: on success, the authoritative
    # write and its ACCEPTED receipt commit together; on failure, no
    # authoritative write happens and a REJECTED/FAILED receipt
    # records why.

    def grant(
        self,
        *,
        requester_identity_id: str,
        authority_grant_id: str,
        identity_id: str,
        authority_id: str,
        valid_from: str | None = None,
        expires_at: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """
        Grant an existing authority to an existing identity.

        requester_identity_id must hold authority_grant_id, and that
        grant must be root -- see _validate_root_grant. Non-root
        identities cannot reach this method at all, so there is no
        delegation and no amplification question to bound in v0.1:
        root is unrestricted, and nothing else can grant/revoke/
        revoke_all/define_authority.

        identity_id and authority_id must already exist. This method
        does not create either one -- identity creation stays in
        transition()'s new_identities; authority definition is its
        own root-only Authority operation, see define_authority.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            if not identity_id:
                raise StateError("identity_id is required")

            if not authority_id:
                raise StateError("authority_id is required")

            new_grant_id = new_id("grant")
            created_at = utc_now()
            grant_valid_from = valid_from or created_at
            receipt_id = new_id("receipt")

            with self.transaction() as conn:
                self._validate_root_grant(
                    conn,
                    authority_grant_id,
                    requester_identity_id,
                )

                identity_exists = conn.execute(
                    "SELECT 1 FROM identities WHERE identity_id = ?",
                    (identity_id,),
                ).fetchone()

                if identity_exists is None:
                    raise StateError(
                        f"identity does not exist: {identity_id}"
                    )

                authority_exists = conn.execute(
                    "SELECT 1 FROM authorities WHERE authority_id = ?",
                    (authority_id,),
                ).fetchone()

                if authority_exists is None:
                    raise StateError(
                        f"authority does not exist: {authority_id}"
                    )

                conn.execute(
                    """
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_grant_id,
                        identity_id,
                        authority_id,
                        requester_identity_id,
                        created_at,
                        grant_valid_from,
                        expires_at,
                        encode_payload(payload),
                    ),
                )

                conn.execute(
                    """
                    INSERT INTO receipts (
                        receipt_id,
                        operation_id,
                        transition_id,
                        outcome,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, NULL, 'ACCEPTED', ?, ?)
                    """,
                    (
                        receipt_id,
                        operation_id,
                        created_at,
                        encode_payload(
                            {
                                "action": "GRANT",
                                "grant_id": new_grant_id,
                                "identity_id": identity_id,
                                "authority_id": authority_id,
                                "authority_grant_id": authority_grant_id,
                                "caused_by_identity_id":
                                    requester_identity_id,
                            }
                        ),
                    ),
                )

            return {
                "operation_id": operation_id,
                "grant_id": new_grant_id,
                "receipt_id": receipt_id,
            }

        except KernelError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="REJECTED",
                reason=str(exc),
            )

            raise KernelError(
                f"{exc} [receipt={receipt_id}]"
            ) from exc

        except sqlite3.IntegrityError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="sqlite integrity failure",
                details={
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"sqlite integrity failure "
                f"[receipt={receipt_id}]"
            ) from exc

        except Exception as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="unexpected kernel operation failure",
                details={
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"unexpected kernel operation failure "
                f"[receipt={receipt_id}]"
            ) from exc

    def revoke(
        self,
        *,
        requester_identity_id: str,
        authority_grant_id: str,
        grant_id: str,
        reason: str | None = None,
    ) -> dict[str, str]:
        """
        Revoke a specific authority grant.

        requester_identity_id must hold authority_grant_id, and that
        grant must be root -- see _validate_root_grant. Non-root
        identities cannot call this at all, including to revoke
        their own grants.

        Refuses to commit if grant_id is currently a valid root
        grant and revoking it would leave zero currently-valid root
        grants kernel-wide (see _count_other_valid_root_grants) --
        evaluated inside this same serialized transaction, so a
        concurrent second revoke of a different root grant cannot
        race around the check either.

        The target grant's row in authority_grants is never mutated
        or deleted -- revocation is recorded entirely as a new,
        separate, immutable ACCEPTED receipt with a reserved
        "action": "REVOKE" payload key. See is_grant_revoked for how
        this is read back. This is permanent and unconditional: once
        revoked, grant_id can never again authorize an operation,
        regardless of which State or branch the attempt is made from.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            created_at = utc_now()
            receipt_id = new_id("receipt")

            with self.transaction() as conn:
                self._validate_root_grant(
                    conn,
                    authority_grant_id,
                    requester_identity_id,
                )

                target_grant = self._get_grant(conn, grant_id)

                if target_grant is None:
                    raise AuthorityError(
                        f"authority grant does not exist: {grant_id}"
                    )

                if self._grant_is_root(
                    conn, target_grant
                ) and not self._is_grant_revoked(conn, grant_id):
                    if self._count_other_valid_root_grants(
                        conn, excluding_grant_ids={grant_id}
                    ) == 0:
                        raise AuthorityError(
                            f"refusing to revoke {grant_id}: it is "
                            f"the last currently-valid root grant -- "
                            f"no accepted Authority operation may "
                            f"leave the kernel with zero root grants"
                        )

                receipt_payload = {
                    "action": "REVOKE",
                    "grant_id": grant_id,
                    "identity_id": target_grant["identity_id"],
                    "authority_grant_id": authority_grant_id,
                    "caused_by_identity_id": requester_identity_id,
                }

                if reason:
                    receipt_payload["reason"] = reason

                conn.execute(
                    """
                    INSERT INTO receipts (
                        receipt_id,
                        operation_id,
                        transition_id,
                        outcome,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, NULL, 'ACCEPTED', ?, ?)
                    """,
                    (
                        receipt_id,
                        operation_id,
                        created_at,
                        encode_payload(receipt_payload),
                    ),
                )

            return {
                "operation_id": operation_id,
                "grant_id": grant_id,
                "receipt_id": receipt_id,
            }

        except KernelError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="REJECTED",
                reason=str(exc),
            )

            raise KernelError(
                f"{exc} [receipt={receipt_id}]"
            ) from exc

        except sqlite3.IntegrityError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="sqlite integrity failure",
                details={
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"sqlite integrity failure "
                f"[receipt={receipt_id}]"
            ) from exc

        except Exception as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="unexpected kernel operation failure",
                details={
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"unexpected kernel operation failure "
                f"[receipt={receipt_id}]"
            ) from exc

    def revoke_all(
        self,
        *,
        requester_identity_id: str,
        authority_grant_id: str,
        identity_id: str,
        reason: str | None = None,
    ) -> dict[str, str]:
        """
        Revoke every grant an identity holds as of this operation.

        requester_identity_id must hold authority_grant_id, and that
        grant must be root -- see _validate_root_grant. Non-root
        identities cannot call this at all, including against their
        own grants.

        Refuses to commit -- entirely, not partially -- if
        identity_id currently holds one or more valid root grants and
        revoking all of them would leave zero currently-valid root
        grants kernel-wide (see _count_other_valid_root_grants).
        revoke_all is all-or-nothing per identity, so this is checked
        for the whole set before anything commits, inside the same
        serialized transaction as the operation itself.

        Recorded as a single immutable ACCEPTED receipt with a
        reserved "action": "REVOKE_ALL" payload key naming
        identity_id. See is_grant_revoked for how this is read back:
        every grant with created_at <= this receipt's created_at is
        invalidated; a grant created after this receipt for the same
        identity is unaffected -- this revokes what existed at this
        moment, it does not ban the identity going forward.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            if not identity_id:
                raise StateError("identity_id is required")

            created_at = utc_now()
            receipt_id = new_id("receipt")

            receipt_payload = {
                "action": "REVOKE_ALL",
                "identity_id": identity_id,
                "authority_grant_id": authority_grant_id,
                "caused_by_identity_id": requester_identity_id,
            }

            if reason:
                receipt_payload["reason"] = reason

            with self.transaction() as conn:
                self._validate_root_grant(
                    conn,
                    authority_grant_id,
                    requester_identity_id,
                )

                identity_exists = conn.execute(
                    "SELECT 1 FROM identities WHERE identity_id = ?",
                    (identity_id,),
                ).fetchone()

                if identity_exists is None:
                    raise StateError(
                        f"identity does not exist: {identity_id}"
                    )

                target_grant_ids = {
                    row["grant_id"]
                    for row in conn.execute(
                        "SELECT grant_id FROM authority_grants "
                        "WHERE identity_id = ?",
                        (identity_id,),
                    ).fetchall()
                }

                identitys_valid_root_grant_ids = {
                    grant_id
                    for grant_id in target_grant_ids
                    if not self._is_grant_revoked(conn, grant_id)
                    and self._grant_is_root(
                        conn, self._get_grant(conn, grant_id)
                    )
                }

                if (
                    identitys_valid_root_grant_ids
                    and self._count_other_valid_root_grants(
                        conn,
                        excluding_grant_ids=identitys_valid_root_grant_ids,
                    )
                    == 0
                ):
                    raise AuthorityError(
                        f"refusing revoke_all for {identity_id}: it "
                        f"currently holds the only remaining valid "
                        f"root grant(s) -- no accepted Authority "
                        f"operation may leave the kernel with zero "
                        f"root grants"
                    )

                conn.execute(
                    """
                    INSERT INTO receipts (
                        receipt_id,
                        operation_id,
                        transition_id,
                        outcome,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, NULL, 'ACCEPTED', ?, ?)
                    """,
                    (
                        receipt_id,
                        operation_id,
                        created_at,
                        encode_payload(receipt_payload),
                    ),
                )

            return {
                "operation_id": operation_id,
                "identity_id": identity_id,
                "receipt_id": receipt_id,
            }

        except KernelError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="REJECTED",
                reason=str(exc),
            )

            raise KernelError(
                f"{exc} [receipt={receipt_id}]"
            ) from exc

        except sqlite3.IntegrityError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="sqlite integrity failure",
                details={
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"sqlite integrity failure "
                f"[receipt={receipt_id}]"
            ) from exc

        except Exception as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="unexpected kernel operation failure",
                details={
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"unexpected kernel operation failure "
                f"[receipt={receipt_id}]"
            ) from exc

    def define_authority(
        self,
        *,
        requester_identity_id: str,
        authority_grant_id: str,
        authority_id: str,
        is_root: bool = False,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """
        Define a new authority. is_root sets the kernel-enforced
        authorities.is_root column directly -- payload carries no
        root-related meaning at all, and never has for this method.

        requester_identity_id must hold authority_grant_id, and that
        grant must be root -- see _validate_root_grant. This closes
        the escalation path where an arbitrary identity could define
        its own authority and mark it root: defining ANY authority,
        root or not, itself requires an existing root grant. Because
        define_authority is already root-only, root defining another
        root authority (is_root=True) is simply an authorized root
        operation like any other -- no additional check is needed
        for that case specifically.

        This was previously done as a side effect of transition()'s
        new_authorities parameter, exercisable by any currently-valid
        grant with no check at all. It is now its own explicit,
        root-only Authority operation, with no State transition
        involved, matching grant/revoke/revoke_all.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            if not authority_id:
                raise StateError("authority_id is required")

            created_at = utc_now()
            receipt_id = new_id("receipt")

            with self.transaction() as conn:
                self._validate_root_grant(
                    conn,
                    authority_grant_id,
                    requester_identity_id,
                )

                already_exists = conn.execute(
                    "SELECT 1 FROM authorities WHERE authority_id = ?",
                    (authority_id,),
                ).fetchone()

                if already_exists is not None:
                    raise StateError(
                        f"authority already exists: {authority_id}"
                    )

                conn.execute(
                    """
                    INSERT INTO authorities (
                        authority_id,
                        created_at,
                        is_root,
                        payload
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        authority_id,
                        created_at,
                        1 if is_root else 0,
                        encode_payload(payload),
                    ),
                )

                conn.execute(
                    """
                    INSERT INTO receipts (
                        receipt_id,
                        operation_id,
                        transition_id,
                        outcome,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, NULL, 'ACCEPTED', ?, ?)
                    """,
                    (
                        receipt_id,
                        operation_id,
                        created_at,
                        encode_payload(
                            {
                                "action": "DEFINE_AUTHORITY",
                                "authority_id": authority_id,
                                "is_root": is_root,
                                "authority_grant_id": authority_grant_id,
                                "caused_by_identity_id":
                                    requester_identity_id,
                            }
                        ),
                    ),
                )

            return {
                "operation_id": operation_id,
                "authority_id": authority_id,
                "receipt_id": receipt_id,
            }

        except KernelError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="REJECTED",
                reason=str(exc),
            )

            raise KernelError(
                f"{exc} [receipt={receipt_id}]"
            ) from exc

        except sqlite3.IntegrityError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="sqlite integrity failure",
                details={
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"sqlite integrity failure "
                f"[receipt={receipt_id}]"
            ) from exc

        except Exception as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="unexpected kernel operation failure",
                details={
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"unexpected kernel operation failure "
                f"[receipt={receipt_id}]"
            ) from exc

    # ---------------------------------------------------------
    # TRANSITIONS
    # ---------------------------------------------------------

    def transition(
        self,
        *,
        requester_identity_id: str,
        from_state_id: str,
        authority_grant_id: str,
        new_state_payload: dict[str, Any],
        transition_payload: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        invariant_ids: list[str] | None = None,
        new_identities: list[dict[str, Any]] | None = None,
    ) -> dict[str, str]:
        """
        Commit an authoritative state transition.

        requester_identity_id is the identity actually attempting the
        operation. The kernel verifies that this identity is the one
        the presented authority_grant_id was issued to -- possession
        of a grant_id alone is not sufficient to exercise it.

        transition() may create State/Transition only -- State
        operations change State, Authority operations change
        Authority. It cannot create or revoke an authority_grants
        row, and cannot define a new authorities row, under any
        circumstances, regardless of what authority the requester
        holds. See the standalone grant/revoke/revoke_all/
        define_authority methods for those. (v0.1 previously
        accepted new_authorities/new_grants parameters here; they
        were removed because they let ANY currently-valid grant --
        including a deliberately narrow one -- mint an arbitrary new
        authority_grants row, including one referencing a root
        authority, with no check at all on the requester's own
        authority. That bypass is closed structurally by removing
        the capability, not by adding another root check to a second
        code path that duplicates grant()'s.)

        On success, state + transition + associations + receipt
        are committed atomically.

        On validation failure, no authoritative state changes.
        A separate rejection receipt/exception is recorded.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            # -------------------------------------------------
            # Validate source state.
            # -------------------------------------------------

            from_state = self.get_state(from_state_id)

            if from_state is None:
                raise StateError(
                    f"source state does not exist: {from_state_id}"
                )

            # -------------------------------------------------
            # Future invariant evaluation belongs here.
            #
            # For v0.1, invariant IDs are provenance references.
            # We are NOT pretending they have been evaluated yet.
            # -------------------------------------------------

            evidence_ids = evidence_ids or []
            invariant_ids = invariant_ids or []
            new_identities = new_identities or []

            for identity in new_identities:
                identity_id = identity.get("identity_id")
                if not isinstance(identity_id, str) or not identity_id:
                    raise StateError(
                        "new identity requires a non-empty identity_id"
                    )

            # -------------------------------------------------
            # Generate immutable IDs before transaction.
            # -------------------------------------------------

            state_id = new_id("state")
            transition_id = new_id("transition")
            receipt_id = new_id("receipt")
            created_at = utc_now()

            # -------------------------------------------------
            # Atomic authoritative commit.
            # -------------------------------------------------

            with self.transaction() as conn:

                # Re-check source state inside the write
                # transaction rather than trusting only the
                # earlier read.

                source_exists = conn.execute(
                    """
                    SELECT 1
                    FROM states
                    WHERE state_id = ?
                    """,
                    (from_state_id,),
                ).fetchone()

                if source_exists is None:
                    raise StateError(
                        f"source state disappeared: {from_state_id}"
                    )

                # Validate authority: grant exists, is temporally
                # valid, has not been revoked, and is actually held
                # by the requesting identity. This happens inside
                # the write transaction -- after BEGIN IMMEDIATE has
                # already taken the write lock -- specifically so
                # that a concurrent revoke cannot commit in a gap
                # between reading this and writing the transition
                # that depends on it. See _validate_grant's
                # docstring.

                grant = self._validate_grant(
                    conn,
                    authority_grant_id,
                    requester_identity_id=requester_identity_id,
                )

                # New identities created by this transition.
                #
                # Identity creation is part of the same authoritative
                # transaction as the state transition. Merely appearing
                # in a state payload does not create kernel identity.

                for identity in new_identities:
                    conn.execute(
                        """
                        INSERT INTO identities (
                            identity_id,
                            created_at,
                            payload
                        )
                        VALUES (?, ?, ?)
                        """,
                        (
                            identity["identity_id"],
                            created_at,
                            encode_payload(identity.get("payload")),
                        ),
                    )

                # New immutable state.

                conn.execute(
                    """
                    INSERT INTO states (
                        state_id,
                        created_at,
                        payload
                    )
                    VALUES ( ?, ?, ?)
                    """,
                    (
                        state_id,
                        created_at,
                        encode_payload(new_state_payload),
                    ),
                )

                # Authoritative transition.

                conn.execute(
                    """
                    INSERT INTO transitions (
                        transition_id,
                        from_state_id,
                        to_state_id,
                        authority_grant_id,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transition_id,
                        from_state_id,
                        state_id,
                        authority_grant_id,
                        created_at,
                        encode_payload(
                            {
                                **(transition_payload or {}),
                                "identity_id": grant["identity_id"],
                                "requester_identity_id":
                                    requester_identity_id,
                            }
                        ),
                    ),
                )

                # Evidence references.

                for evidence_id in evidence_ids:
                    conn.execute(
                        """
                        INSERT INTO transition_evidence (
                            transition_id,
                            evidence_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            transition_id,
                            evidence_id,
                        ),
                    )

                # Invariant references.

                for invariant_id in invariant_ids:
                    conn.execute(
                        """
                        INSERT INTO transition_invariants (
                            transition_id,
                            invariant_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            transition_id,
                            invariant_id,
                        ),
                    )

                # Success receipt.

                conn.execute(
                    """
                    INSERT INTO receipts (
                        receipt_id,
                        operation_id,
                        transition_id,
                        outcome,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, ?, 'ACCEPTED', ?, ?)
                    """,
                    (
                        receipt_id,
                        operation_id,
                        transition_id,
                        created_at,
                        encode_payload(
                            {
                                "from_state_id": from_state_id,
                                "to_state_id": state_id,
                                "authority_grant_id":
                                    authority_grant_id,
                            }
                        ),
                    )
                )
            return {
                "operation_id": operation_id,
                "state_id": state_id,
                "transition_id": transition_id,
                "receipt_id": receipt_id,
            }

        except KernelError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="REJECTED",
                reason=str(exc),
            )

            raise KernelError(
                f"{exc} [receipt={receipt_id}]"
            ) from exc

        except sqlite3.IntegrityError as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="sqlite integrity failure",
                details={
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"sqlite integrity failure "
                f"[receipt={receipt_id}]"
            ) from exc

        except  Exception as exc:
            receipt_id = self.record_failure(
                operation_id=operation_id,
                outcome="FAILED",
                reason="unexpected kernel operation failure",
                details={
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

            raise KernelError(
                f"unexpected kernel operation failure "
                f"[receipt={receipt_id}]"
            ) from exc 

# -------------------------------------------------------------
# Minimal command-line smoke test
# -------------------------------------------------------------

if __name__ == "__main__":
    kernel = Kernel()

    print("Intelligence Kernel v0.1")
    print()

    genesis = kernel.get_genesis_state()

    print("Genesis:")
    print(json.dumps(genesis, indent=2))

    print()

    grant = kernel.validate_grant("grant:genesis-root")

    print("Genesis authority grant:")
    print(json.dumps(grant, indent=2))
