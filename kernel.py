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

    def validate_grant(
        self,
        grant_id: str,
        at_time: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate that a grant exists and is temporally valid.

        v0.1 currently validates:
            - grant exists
            - valid_from has been reached
            - expires_at has not been reached

        Revocation is intentionally not implemented yet.
        """

        grant = self.get_grant(grant_id)

        if grant is None:
            raise AuthorityError(
                f"authority grant does not exist: {grant_id}"
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
        from_state_id: str,
        authority_grant_id: str,
        new_state_payload: dict[str, Any],
        transition_payload: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        invariant_ids: list[str] | None = None,
    ) -> dict[str, str]:
        """
        Commit an authoritative state transition.

        On success, state + transition + associations + receipt
        are committed atomically.

        On validation failure, no authoritative state changes.
        A separate rejection receipt/exception is recorded.
        """

        operation_id = new_id("operation")

        try:
            # -------------------------------------------------
            # Validate source state.
            # -------------------------------------------------

            from_state = self.get_state(from_state_id)

            if from_state is None:
                raise StateError(
                    f"source state does not exist: {from_state_id}"
                )

            # -------------------------------------------------
            # Validate authority.
            # -------------------------------------------------

            grant = self.validate_grant(authority_grant_id)

            # -------------------------------------------------
            # Future invariant evaluation belongs here.
            #
            # For v0.1, invariant IDs are provenance references.
            # We are NOT pretending they have been evaluated yet.
            # -------------------------------------------------

            evidence_ids = evidence_ids or []
            invariant_ids = invariant_ids or []

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
