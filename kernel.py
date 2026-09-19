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

    def get_grant(self, grant_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
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

    # ---------------------------------------------------------
    # AUTHORITY
    # ---------------------------------------------------------

    def is_grant_superseded(self, grant_id: str) -> bool:
        """
        Whether any committed transition has declared this grant
        superseded.

        This uses no schema beyond the existing transitions table.
        transitions.payload is already opaque, kernel-agnostic JSON
        (design principle 5: "userland meaning lives in JSON
        payloads, not schema"). A committed transition may carry a
        reserved "supersedes_grant_ids" key in that payload; this is
        a Python-side *semantic* law (design principle 4), not a
        structural one, so it is evaluated here rather than in
        SQLite. Only rows in the transitions table are considered --
        rejected/failed attempts never reach it, so an attempted-but-
        rejected supersession cannot count.
        """

        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM transitions"
            ).fetchall()

        for row in rows:
            payload = json.loads(row["payload"])
            superseded_ids = payload.get("supersedes_grant_ids") or []

            if grant_id in superseded_ids:
                return True

        return False

    def validate_grant(
        self,
        grant_id: str,
        at_time: str | None = None,
        requester_identity_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate that a grant exists, is temporally valid, has not
        been superseded, and (when a requester is given) is actually
        held by the identity attempting to exercise it.

        v0.1 currently validates:
            - grant exists
            - valid_from has been reached
            - expires_at has not been reached
            - grant has not been superseded (see is_grant_superseded)
            - the requesting identity is the identity the grant was
              issued to, when a requester is supplied
        """

        grant = self.get_grant(grant_id)

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

        if self.is_grant_superseded(grant_id):
            raise AuthorityError(
                f"authority grant has been superseded: {grant_id}"
            )

        return grant

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
        new_authorities: list[dict[str, Any]] | None = None,
        new_grants: list[dict[str, Any]] | None = None,
        supersedes_grant_ids: list[str] | None = None,
    ) -> dict[str, str]:
        """
        Commit an authoritative state transition.

        requester_identity_id is the identity actually attempting the
        operation. The kernel verifies that this identity is the one
        the presented authority_grant_id was issued to -- possession
        of a grant_id alone is not sufficient to exercise it.

        supersedes_grant_ids records, inside this transition's own
        payload (no schema change), that the listed grants are no
        longer effective as of this transition. See
        is_grant_superseded for how this is read back.

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
            # Validate authority: grant exists, is temporally
            # valid, has not been superseded, and is actually
            # held by the requesting identity.
            # -------------------------------------------------

            grant = self.validate_grant(
                authority_grant_id,
                requester_identity_id=requester_identity_id,
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
            new_authorities = new_authorities or []
            new_grants = new_grants or []
            supersedes_grant_ids = supersedes_grant_ids or []

            for identity in new_identities:
                identity_id = identity.get("identity_id")
                if not isinstance(identity_id, str) or not identity_id:
                    raise StateError(
                        "new identity requires a non-empty identity_id"
                    )

            for authority in new_authorities:
                authority_id = authority.get("authority_id")
                if not isinstance(authority_id, str) or not authority_id:
                    raise StateError(
                        "new authority requires a non-empty authority_id"
                    )

            for new_grant in new_grants:
                grant_id = new_grant.get("grant_id")
                grant_identity_id = new_grant.get("identity_id")
                grant_authority_id = new_grant.get("authority_id")
                grant_valid_from = new_grant.get("valid_from")

                if not isinstance(grant_id, str) or not grant_id:
                    raise StateError(
                        "new grant requires a non-empty grant_id"
                    )
                if (
                    not isinstance(grant_identity_id, str)
                    or not grant_identity_id
                ):
                    raise StateError(
                        f"new grant {grant_id} requires a non-empty "
                        f"identity_id"
                    )
                if (
                    not isinstance(grant_authority_id, str)
                    or not grant_authority_id
                ):
                    raise StateError(
                        f"new grant {grant_id} requires a non-empty "
                        f"authority_id"
                    )
                if (
                    not isinstance(grant_valid_from, str)
                    or not grant_valid_from
                ):
                    raise StateError(
                        f"new grant {grant_id} requires a non-empty "
                        f"valid_from"
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

                # New authority definitions created by this
                # transition. Existing `authorities` table, no
                # schema change.

                for authority in new_authorities:
                    conn.execute(
                        """
                        INSERT INTO authorities (
                            authority_id,
                            created_at,
                            payload
                        )
                        VALUES (?, ?, ?)
                        """,
                        (
                            authority["authority_id"],
                            created_at,
                            encode_payload(authority.get("payload")),
                        ),
                    )

                # New authority grants created by this transition.
                # Existing `authority_grants` table, no schema
                # change.
                #
                # granted_by_identity_id is always the requester --
                # never caller-supplied -- so a grant's recorded
                # provenance cannot be spoofed to claim a different
                # granting identity than the one the kernel actually
                # verified.

                for new_grant in new_grants:
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
                            new_grant["grant_id"],
                            new_grant["identity_id"],
                            new_grant["authority_id"],
                            requester_identity_id,
                            created_at,
                            new_grant["valid_from"],
                            new_grant.get("expires_at"),
                            encode_payload(new_grant.get("payload")),
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
                                **(
                                    {
                                        "supersedes_grant_ids":
                                            list(supersedes_grant_ids),
                                    }
                                    if supersedes_grant_ids
                                    else {}
                                ),
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
