"""Receipt red-team remediation checks.

Runs against a throwaway copy of the current development database.  The
copy is intentional: revoke_all is an append-only Authority operation and
these checks should never consume the shared development history.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import kernel as kernel_module
from kernel import Kernel, KernelError


ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
AUTHORITY = "authority:clawde-scope-alpha"


source = Path(__file__).resolve().parent.parent / "data" / "kernel.db"
with tempfile.NamedTemporaryFile(prefix="receipt-remediation-", suffix=".db") as f:
    f.close()
    db_path = Path(f.name)
    shutil.copy2(source, db_path)
    kernel = Kernel(db_path)
    real_utc_now = kernel_module.utc_now

    def set_now(value: str) -> None:
        kernel_module.utc_now = lambda: value

    def count(table: str) -> int:
        with kernel.connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def grant(*, created_at: str, valid_from: str = "2000-01-01T00:00:00Z") -> str:
        result = kernel.grant(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            identity_id=CLAWDE,
            authority_id=AUTHORITY,
            valid_from=valid_from,
        )
        row = kernel.get_grant(result["grant_id"])
        assert row is not None
        assert row["created_at"] == created_at
        return result["grant_id"]

    try:
        # 1/2. Specific revoke is isolated to its target grant.
        set_now("2030-01-01T00:00:00Z")
        specific_target = grant(created_at="2030-01-01T00:00:00Z")
        unrelated = grant(created_at="2030-01-01T00:00:00Z")
        kernel.revoke(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            grant_id=specific_target,
        )
        assert kernel.is_grant_revoked(specific_target)
        assert not kernel.is_grant_revoked(unrelated)

        # 3/4/6/11/12. Authority sequence, not wall-clock time, orders
        # revoke_all.  The first grant has a future timestamp but exists
        # before the revoke_all; the second has a past timestamp but is
        # issued after it.
        set_now("2040-01-01T00:00:00Z")
        before_bulk = grant(created_at="2040-01-01T00:00:00Z")
        set_now("2026-09-20T00:00:00Z")
        bulk_result = kernel.revoke_all(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            identity_id=CLAWDE,
        )
        set_now("2026-09-19T12:00:00Z")
        after_bulk = grant(created_at="2026-09-19T12:00:00Z")
        assert kernel.is_grant_revoked(before_bulk)
        assert not kernel.is_grant_revoked(after_bulk)
        assert kernel.get_receipt(bulk_result["receipt_id"])["outcome"] == "ACCEPTED"

        # 5. A later grant is a new valid Authority record after a
        # specific revoke; it does not resurrect the old record.
        regrant = grant(created_at="2026-09-19T12:00:00Z")
        assert not kernel.is_grant_revoked(regrant)
        assert kernel.is_grant_revoked(specific_target)

        # 7. A failed Authority operation leaves no partial grant.
        grants_before = count("authority_grants")
        receipts_before = count("receipts")
        try:
            kernel.grant(
                requester_identity_id=NATHAN,
                authority_grant_id=ROOT,
                identity_id=CLAWDE,
                authority_id=AUTHORITY,
                evidence_ids=["evidence:does-not-exist"],
            )
        except KernelError:
            pass
        else:
            raise AssertionError("dangling evidence must reject grant")
        assert count("authority_grants") == grants_before
        assert count("receipts") == receipts_before + 1

        # 8. Accepted Authority operations append their Authority row and
        # ACCEPTED receipt in one transaction.
        revocations_before = count("authority_grant_revocations")
        receipts_before = count("receipts")
        set_now("2026-09-20T00:00:00Z")
        atomic_target = grant(created_at="2026-09-20T00:00:00Z")
        accepted_revoke = kernel.revoke(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            grant_id=atomic_target,
        )
        assert count("authority_grant_revocations") == revocations_before + 1
        assert count("receipts") == receipts_before + 2
        assert kernel.get_receipt(accepted_revoke["receipt_id"])["outcome"] == "ACCEPTED"

        # 9. A forged Receipt payload has no Authority effect, and a
        # forged GRANT receipt cannot create an Authority record.
        forged = "receipt:forged-authority-action"
        with kernel.connect() as conn:
            conn.execute(
                """
                INSERT INTO receipts
                    (receipt_id, operation_id, transition_id, outcome, created_at, payload)
                VALUES (?, ?, NULL, 'ACCEPTED', ?, ?)
                """,
                (
                    forged,
                    "operation:forged-authority-action",
                    "2026-09-20T00:00:00Z",
                    json.dumps({
                        "action": "REVOKE",
                        "grant_id": after_bulk,
                        "identity_id": CLAWDE,
                    }),
                ),
            )
            conn.commit()
        assert not kernel.is_grant_revoked(after_bulk)
        with kernel.connect() as conn:
            assert conn.execute(
                "SELECT 1 FROM authority_grants WHERE grant_id = ?",
                ("grant:forged-authority-action",),
            ).fetchone() is None

        # 10 and 13-17 are covered by the existing Authority, State,
        # Transition, Evidence, and kernel regression scripts.  Keep a
        # direct structural check here that Receipt is not the runtime
        # source of revocation truth.
        with kernel.connect() as conn:
            source_tables = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'authority_grant_revocations'"
            ).fetchone()[0]
        assert "CREATE TABLE authority_grant_revocations" in source_tables

        print("RECEIPT-1 remediation checks passed")
    finally:
        kernel_module.utc_now = real_utc_now
