#!/usr/bin/env python3
"""
Intelligence Kernel v0.1

Reference Python implementation.

Responsibilities:
    - Own all writes to authoritative SQLite state.
    - Validate authority before committing transitions.
    - Preserve append-only semantics.
    - Commit state + transition + evidence links + receipt atomically.
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
                authority_seq,
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
            "authority_seq": row["authority_seq"],
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

    def _next_authority_seq(self, conn: sqlite3.Connection) -> int:
        """
        Next value in Authority's own append-only kernel-order
        sequence, shared across authority_grants and
        authority_grant_revocations so a grant and a revocation are
        directly comparable by plain integer comparison -- never by
        wall-clock created_at, and deliberately never by
        receipts.receipt_seq either (Receipt's own sequence stays out
        of Authority's validity determination entirely; see
        _is_grant_revoked and the Receipt red-team remediation this
        replaced).

        Safe to compute via MAX(...)+1 here specifically because
        every caller (grant/revoke/revoke_all) holds this conn's
        BEGIN IMMEDIATE write lock already -- the same
        single-writer-serialization guarantee _validate_grant's
        docstring relies on -- so no concurrent writer can insert a
        competing value in the gap between this read and this
        transaction's own insert.
        """

        row = conn.execute(
            """
            SELECT COALESCE(MAX(authority_seq), 0) AS max_seq
            FROM (
                SELECT authority_seq FROM authority_grants
                UNION ALL
                SELECT authority_seq FROM authority_grant_revocations
            )
            """
        ).fetchone()

        return row["max_seq"] + 1

    def _is_grant_revoked(
        self, conn: sqlite3.Connection, grant_id: str
    ) -> bool:
        """
        Whether a standalone Authority REVOKE or REVOKE_ALL operation
        (see revoke/revoke_all below) has invalidated this grant.

        Reads authority_grant_revocations ONLY -- an Authority-owned,
        append-only table -- never receipts. Authority validity is
        Authority-owned data; Receipt records what the kernel did, it
        is not (and, before this fix, should never have been) the
        place Authority validity gets computed from.

        The previous version of this method derived revocation
        entirely by scanning receipts.payload for a reserved "action"
        key, which made Receipt Authority's sole source of truth for
        this fact, and ordered REVOKE_ALL coverage by comparing
        receipt.created_at (wall-clock, captured before the writer's
        BEGIN IMMEDIATE lock) against a grant's created_at. Simulated
        clock skew empirically reproduced both a false-positive (a
        grant issued after a revoke_all treated as already-revoked)
        and a real bypass (a grant that existed and was exercised
        before a revoke_all survived it, with the revoke_all's own
        receipt still reporting ACCEPTED). See the Receipt red-team
        findings and migrate_authority_append_only_revocations.sql.

        REVOKE names one grant_id directly: permanent, unconditional.

        REVOKE_ALL names one identity_id: every grant that identity
        held as of that revocation's authority_seq becomes invalid.
        A grant created after that revocation's authority_seq is
        unaffected -- REVOKE_ALL revokes what existed at that moment,
        it does not ban the identity going forward. Compared using
        authority_seq (Authority's own append-only kernel-order
        sequence, shared across authority_grants and
        authority_grant_revocations -- see _next_authority_seq),
        never wall-clock created_at.
        """

        grant = self._get_grant(conn, grant_id)

        if grant is None:
            return False

        direct = conn.execute(
            """
            SELECT 1
            FROM authority_grant_revocations
            WHERE kind = 'REVOKE'
              AND grant_id = ?
            """,
            (grant_id,),
        ).fetchone()

        if direct is not None:
            return True

        bulk = conn.execute(
            """
            SELECT 1
            FROM authority_grant_revocations
            WHERE kind = 'REVOKE_ALL'
              AND identity_id = ?
              AND authority_seq >= ?
            """,
            (grant["identity_id"], grant["authority_seq"]),
        ).fetchone()

        return bulk is not None

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
        evidence_ids: list[str] | None = None,
    ) -> str:
        """
        Record a failed/rejected kernel operation.

        This creates no state and no authoritative transition.

        The Receipt this produces is deliberately minimal: only
        `reason`, a short kernel-authored classification string (e.g.
        "sqlite integrity failure"), never the caller-supplied
        `details` dict. `details` (raw exception type/message/context)
        is Exception-owned diagnostic information -- it goes into the
        Exception's own payload only. Receipt records that an
        Exception occurred and that the operation failed; Exception
        owns explaining why. The two remain linked through
        exceptions.receipt_id (see the exceptions table), which this
        method always populates, regardless of what caused the
        failure.

        evidence_ids lets a caller preserve Evidence it submitted
        alongside the now-failed attempt (see transition()/grant()/
        revoke()/revoke_all()/define_authority()) by linking it to
        this failure receipt instead. record_failure() must be
        UNCONDITIONALLY able to produce a receipt -- that is the one
        thing every caller relies on no matter what went wrong. If the
        failure itself was caused by a bad evidence_id (e.g. a
        dangling reference), blindly attempting to link that same
        evidence_id here would throw again with no handler above it,
        leaving the operation with NO receipt at all -- a violation of
        design principle 7 ("failed operations leave immutable
        receipts/exceptions"). So this is resolved BEFORE either
        insert below: exceptions is itself append-only/immutable (see
        exceptions_no_update), so the unlinkable list must go into the
        ORIGINAL insert, never a later UPDATE. Only evidence_ids that
        actually exist get linked; anything that doesn't is recorded
        in the exception payload instead of silently dropped or
        allowed to crash the receipt path.

        The caller-supplied `details` dict is Exception-owned diagnostic
        content and is never validated/sanitized by any caller -- it may
        be unencodable (NaN/Infinity, rejected by encode_payload's
        allow_nan=False) or exceed SQLite's json_valid() nesting depth
        limit (currently 1000; see exceptions.payload's
        CHECK(json_valid(...))). Either failure happens INSIDE this
        method's own write transaction, after the Receipt row has
        already been inserted (see the Exception red-team's EXC-7:
        forcing a failure at that exact point confirmed the whole
        transaction rolls back atomically, leaving no receipt at all)
        -- which would otherwise make the "UNCONDITIONALLY able to
        produce a receipt" guarantee above false. So this method
        degrades instead: if `details` cannot be represented, the
        Exception's `details` are replaced with a small, minimal,
        kernel-authored fallback (never a retry of the original
        content in any form) and the FAILED/REJECTED Receipt +
        Exception are still persisted atomically. If even that
        fallback insert fails, the transaction rolls back with no
        receipt at all, exactly as EXC-7 already established for a
        genuine persistence failure -- this method still does not
        pretend to have committed something it did not.
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

        with self.transaction() as conn:
            requested_evidence_ids = evidence_ids or []
            existing_evidence_ids = set()

            if requested_evidence_ids:
                placeholders = ",".join("?" for _ in requested_evidence_ids)
                existing_evidence_ids = {
                    row["evidence_id"]
                    for row in conn.execute(
                        f"SELECT evidence_id FROM evidence "
                        f"WHERE evidence_id IN ({placeholders})",
                        tuple(requested_evidence_ids),
                    ).fetchall()
                }

            unlinkable_evidence_ids = [
                eid for eid in requested_evidence_ids
                if eid not in existing_evidence_ids
            ]

            exception_payload = {
                "reason": reason,
                "details": details or {},
            }

            if unlinkable_evidence_ids:
                exception_payload["unlinkable_evidence_ids"] = (
                    unlinkable_evidence_ids
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

            def insert_exception(payload: dict[str, Any]) -> None:
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
                        encode_payload(payload),
                    ),
                )

            try:
                insert_exception(exception_payload)
            except (
                ValueError,
                TypeError,
                RecursionError,
                sqlite3.IntegrityError,
            ) as encode_exc:
                # ValueError/TypeError/RecursionError: encode_payload
                # itself failed on `details` before any SQL ran (e.g.
                # NaN/Infinity, or a future serializer failure of
                # comparable type). sqlite3.IntegrityError: encode_payload
                # succeeded but SQLite's json_valid() CHECK rejected the
                # result (currently: nesting depth > 1000) -- catching
                # this one is deliberately narrowed to json_valid
                # specifically, so an unrelated IntegrityError (e.g. a
                # real bug tripping the receipt_id UNIQUE/FK constraints)
                # still surfaces instead of being silently reinterpreted
                # as an encoding problem.
                if (
                    isinstance(encode_exc, sqlite3.IntegrityError)
                    and "json_valid" not in str(encode_exc)
                ):
                    raise

                fallback_payload = {
                    "reason": reason,
                    "details": {
                        "kernel_fallback": True,
                        "reason": (
                            "original diagnostic details could not be "
                            "represented in the kernel's accepted "
                            "JSON/SQLite encoding"
                        ),
                        "encode_error_type": type(encode_exc).__name__,
                    },
                }

                if unlinkable_evidence_ids:
                    fallback_payload["unlinkable_evidence_ids"] = (
                        unlinkable_evidence_ids
                    )

                # No try/except here: if even this minimal, kernel-
                # authored fallback cannot be persisted, that is a
                # genuine persistence failure, not an encoding problem
                # with caller data -- it propagates out of
                # record_failure() entirely and self.transaction()
                # rolls back the whole attempt (Receipt included),
                # exactly as EXC-7 established for that case.
                insert_exception(fallback_payload)

            # Evidence submitted alongside a failed/rejected attempt is
            # linked to this failure receipt in this SAME transaction --
            # never the rolled-back attempt's own transaction -- so
            # preserving it can never resurrect any authoritative
            # State/Transition/Authority write.
            for evidence_id in requested_evidence_ids:
                if evidence_id not in existing_evidence_ids:
                    continue
                conn.execute(
                    """
                    INSERT INTO receipt_evidence (
                        receipt_id,
                        evidence_id
                    )
                    VALUES (?, ?)
                    """,
                    (
                        receipt_id,
                        evidence_id,
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
    # Each writes into Authority-owned tables (authority_grants for
    # grant; authority_grant_revocations for revoke/revoke_all) plus
    # receipts, and follows the same atomicity/failure-receipt
    # pattern as transition() below: on success, the authoritative
    # write(s) and their ACCEPTED receipt commit together, in that
    # order -- Authority record(s) first, receipt referencing them
    # second, since the receipt is provenance about the Authority
    # change, not the source of it (see _is_grant_revoked). On
    # failure, no authoritative write happens and a REJECTED/FAILED
    # receipt records why.

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
        evidence_ids: list[str] | None = None,
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

        evidence_ids optionally cites already-admitted Evidence (see
        record_evidence()) in support of this operation's Receipt.
        Purely optional and inert -- it can never affect whether the
        grant is accepted, only which Evidence ends up linked to the
        resulting Receipt. A dangling evidence_id rolls back the whole
        attempt, same as everything else in this atomic transaction
        (see transition() for why); on failure, valid evidence_ids are
        still preserved against the failure Receipt via
        record_failure().
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

                new_authority_seq = self._next_authority_seq(conn)

                conn.execute(
                    """
                    INSERT INTO authority_grants (
                        grant_id,
                        authority_seq,
                        identity_id,
                        authority_id,
                        granted_by_identity_id,
                        created_at,
                        valid_from,
                        expires_at,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_grant_id,
                        new_authority_seq,
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

                for evidence_id in evidence_ids or []:
                    conn.execute(
                        """
                        INSERT INTO receipt_evidence (
                            receipt_id,
                            evidence_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            receipt_id,
                            evidence_id,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
        evidence_ids: list[str] | None = None,
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
        separate, immutable Authority-owned row in
        authority_grant_revocations (kind='REVOKE'), which is what
        is_grant_revoked reads back; the ACCEPTED receipt this
        operation also produces references that row for provenance
        only, it does not itself establish revocation (see the
        Receipt red-team remediation). This is permanent and
        unconditional: once revoked, grant_id can never again
        authorize an operation, regardless of which State or branch
        the attempt is made from.

        evidence_ids optionally cites already-admitted Evidence (see
        record_evidence()) in support of this operation's Receipt --
        e.g. why the grant is being revoked. Purely optional and
        inert: it can never affect whether the revoke is accepted.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            created_at = utc_now()
            receipt_id = new_id("receipt")
            revocation_id = new_id("revocation")

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

                revocation_payload = {}

                if reason:
                    revocation_payload["reason"] = reason

                # Authoritative Authority record. Inserted BEFORE the
                # receipt below -- this is the actual authoritative
                # change; the receipt only references it for
                # provenance (see _is_grant_revoked/red-team
                # remediation: Authority validity must never be
                # computed by interpreting receipts.payload).

                new_authority_seq = self._next_authority_seq(conn)

                conn.execute(
                    """
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
                    VALUES (?, ?, 'REVOKE', ?, NULL, ?, ?, ?, ?)
                    """,
                    (
                        revocation_id,
                        new_authority_seq,
                        grant_id,
                        requester_identity_id,
                        authority_grant_id,
                        created_at,
                        encode_payload(revocation_payload),
                    ),
                )

                receipt_payload = {
                    "action": "REVOKE",
                    "revocation_id": revocation_id,
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

                for evidence_id in evidence_ids or []:
                    conn.execute(
                        """
                        INSERT INTO receipt_evidence (
                            receipt_id,
                            evidence_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            receipt_id,
                            evidence_id,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
        evidence_ids: list[str] | None = None,
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

        Recorded as a single immutable Authority-owned row in
        authority_grant_revocations (kind='REVOKE_ALL') naming
        identity_id. See is_grant_revoked for how this is read back:
        every grant with authority_seq <= this row's authority_seq is
        invalidated; a grant created after this row (in Authority's
        own kernel-order sequence, never wall-clock time) for the
        same identity is unaffected -- this revokes what existed at
        this moment, it does not ban the identity going forward. The
        ACCEPTED receipt this operation also produces references that
        row for provenance only; it does not itself establish
        revocation (see the Receipt red-team remediation).

        evidence_ids optionally cites already-admitted Evidence (see
        record_evidence()) in support of this operation's Receipt.
        Purely optional and inert: it can never affect whether the
        revoke_all is accepted.
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
            revocation_id = new_id("revocation")

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

                revocation_payload = {}

                if reason:
                    revocation_payload["reason"] = reason

                # Authoritative Authority record. Inserted BEFORE the
                # receipt below -- same reasoning as revoke() (see
                # its comment): the receipt only references this row
                # for provenance, it does not establish revocation.

                new_authority_seq = self._next_authority_seq(conn)

                conn.execute(
                    """
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
                    VALUES (?, ?, 'REVOKE_ALL', NULL, ?, ?, ?, ?, ?)
                    """,
                    (
                        revocation_id,
                        new_authority_seq,
                        identity_id,
                        requester_identity_id,
                        authority_grant_id,
                        created_at,
                        encode_payload(revocation_payload),
                    ),
                )

                receipt_payload = {
                    "action": "REVOKE_ALL",
                    "revocation_id": revocation_id,
                    "identity_id": identity_id,
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

                for evidence_id in evidence_ids or []:
                    conn.execute(
                        """
                        INSERT INTO receipt_evidence (
                            receipt_id,
                            evidence_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            receipt_id,
                            evidence_id,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
        evidence_ids: list[str] | None = None,
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

        evidence_ids optionally cites already-admitted Evidence (see
        record_evidence()) in support of this operation's Receipt.
        Purely optional and inert: it can never affect whether the
        authority definition is accepted.
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

                for evidence_id in evidence_ids or []:
                    conn.execute(
                        """
                        INSERT INTO receipt_evidence (
                            receipt_id,
                            evidence_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            receipt_id,
                            evidence_id,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
            )

            raise KernelError(
                f"unexpected kernel operation failure "
                f"[receipt={receipt_id}]"
            ) from exc

    # ---------------------------------------------------------
    # EVIDENCE
    # ---------------------------------------------------------
    #
    # record_evidence() is Evidence's own admission/existence
    # operation -- distinct from receipt_evidence, which is
    # ASSOCIATION of already-existing Evidence with some OTHER,
    # possibly-later operation's Receipt (see the evidence_ids
    # parameter on transition/grant/revoke/revoke_all/
    # define_authority above).
    #
    # Deliberately NOT root-gated: unlike grant/revoke/revoke_all/
    # define_authority (which alter the capability graph itself and
    # so require root, closing the amplification question), admitting
    # Evidence cannot grant Authority, alter State, or validate an
    # otherwise-invalid operation -- it is inert reference material
    # (see transition()'s own evidence_ids, likewise open to any
    # currently-valid grant). Any currently-valid grant, root or not,
    # may call this -- same authorization bar as transition(), not the
    # Authority-admin bar.
    #
    # This method does NOT create a receipt_evidence row linking the
    # new Evidence to its own creation Receipt. Provenance of WHO
    # admitted this Evidence and WHEN lives entirely in this
    # operation's own kernel-authored receipt payload (action,
    # evidence_id, authority_grant_id, caused_by_identity_id) --
    # exactly the same place transition()'s provenance lives
    # (identity_id/requester_identity_id in the transition's own
    # receipt payload, not some separate junction row) -- and exactly
    # why the evidence/states tables carry no created_by column of
    # their own: creation provenance belongs to the operation that
    # produced the row, not the row itself.
    #
    # Self-linking the creation receipt to its own evidence was
    # considered and rejected: receipt_evidence is defined to mean
    # "Evidence E was cited/submitted in SUPPORT of Receipt R" (R
    # belongs to some other, later operation this Evidence was offered
    # alongside). A creation receipt's relationship to the Evidence it
    # just brought into existence is the opposite relationship (R
    # produced E, E does not support R) -- collapsing both into one
    # junction table would make every future "what evidence supports
    # this receipt" query ambiguous for exactly one row per Evidence
    # object: its own birth receipt. Kernel-mechanically this creates
    # no authority or validity problem (nothing reads receipt_evidence
    # to make a decision -- see the evidence-is-inert guarantee tested
    # throughout this file), but it is an avoidable modeling defect,
    # so it is avoided.

    def record_evidence(
        self,
        *,
        requester_identity_id: str,
        authority_grant_id: str,
        payload: dict[str, Any],
    ) -> dict[str, str]:
        """
        Admit a new immutable Evidence object.

        This is Evidence's existence/admission operation. It says
        nothing about what the evidence is offered in support of --
        that is a separate, later act of ASSOCIATION (see
        evidence_ids on transition/grant/revoke/revoke_all/
        define_authority), performed by naming this evidence_id when
        some other operation is attempted. A freshly admitted
        evidence_id cannot be cited by anything until this call has
        committed -- association always happens strictly after
        admission, never inside the same transaction, so there is no
        same-call recursion to reason about.

        requester_identity_id must hold authority_grant_id, and that
        grant must be currently valid -- but need NOT be root. See
        the class comment above for why.

        payload is opaque caller-supplied material or a reference to
        material. The kernel does not interpret it, verify it, or
        assert it is true, authentic, relevant, or that anything it
        references still exists.
        """

        operation_id = new_id("operation")

        try:
            if not requester_identity_id:
                raise AuthorityError(
                    "requester_identity_id is required"
                )

            if payload is None:
                raise StateError(
                    "evidence payload is required (may be an empty "
                    "object, but not omitted)"
                )

            new_evidence_id = new_id("evidence")
            created_at = utc_now()
            receipt_id = new_id("receipt")

            with self.transaction() as conn:
                grant = self._validate_grant(
                    conn,
                    authority_grant_id,
                    requester_identity_id=requester_identity_id,
                )

                conn.execute(
                    """
                    INSERT INTO evidence (
                        evidence_id,
                        created_at,
                        payload
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        new_evidence_id,
                        created_at,
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
                                "action": "RECORD_EVIDENCE",
                                "evidence_id": new_evidence_id,
                                "authority_grant_id": authority_grant_id,
                                "caused_by_identity_id":
                                    grant["identity_id"],
                            }
                        ),
                    ),
                )

            return {
                "operation_id": operation_id,
                "evidence_id": new_evidence_id,
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

        Replay/branching (frozen State design decision): this method
        performs no deduplication. Calling it twice with identical
        arguments -- e.g. a naive retry after a timeout -- commits
        two distinct states, each a valid separate branch from the
        same from_state_id; neither is preferred, and the kernel does
        not merge them. There is no canonical-head/current-state
        concept anywhere in this kernel -- which state_id to continue
        from on the next call is entirely a userland decision, made
        fresh each time. If userland cannot resolve which of several
        branches to continue from, that escalation (e.g. to Nathan/
        root) happens entirely outside the kernel; the kernel has no
        role in choosing and enforces none.
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

            evidence_ids = evidence_ids or []
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

                # Success receipt. Must be inserted BEFORE the evidence
                # links below -- receipt_evidence.receipt_id is a
                # foreign key into receipts, and SQLite checks foreign
                # keys immediately per-statement (not deferred), so the
                # receipt row must already exist in this same
                # transaction before anything can reference it.

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

                # Evidence references -- linked to this transition's
                # success RECEIPT, not the transition row itself, so
                # the same mechanism also works for Authority-operation
                # receipts and REJECTED/FAILED receipts (see
                # record_failure). Inserted after the receipt row above
                # so the receipt_evidence.receipt_id foreign key always
                # resolves.

                for evidence_id in evidence_ids:
                    conn.execute(
                        """
                        INSERT INTO receipt_evidence (
                            receipt_id,
                            evidence_id
                        )
                        VALUES (?, ?)
                        """,
                        (
                            receipt_id,
                            evidence_id,
                        ),
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
                evidence_ids=evidence_ids,
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
