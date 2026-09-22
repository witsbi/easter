"""Receipt final cleanup checks: FAILED Receipt minimality + Exception
JSON structural hardening.

Runs against a throwaway copy of the current development database, since
these checks intentionally exercise failure paths against append-only
tables and should never consume shared development history.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from kernel import Kernel, KernelError


ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = [
        "states", "transitions", "receipts", "exceptions",
        "authority_grants", "authority_grant_revocations",
        "evidence", "receipt_evidence", "identities",
    ]
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}


source = Path(__file__).resolve().parent.parent / "data" / "kernel.db"
with tempfile.NamedTemporaryFile(prefix="receipt-minimality-", suffix=".db") as f:
    f.close()
    db_path = Path(f.name)
    shutil.copy2(source, db_path)
    kernel = Kernel(db_path)

    # 1/2/4. A genuine unexpected failure (real sqlite3.IntegrityError,
    # not a kernel-rule KernelError) produces a FAILED Receipt whose
    # payload does NOT duplicate diagnostic `details`, while the
    # associated Exception retains them, and the two stay linked.
    with kernel.connect() as conn:
        before = counts(conn)

    try:
        kernel.transition(
            requester_identity_id=NATHAN,
            from_state_id=GENESIS,
            authority_grant_id=ROOT,
            new_state_payload={"probe": "receipt-2-minimality"},
            evidence_ids=["evidence:does-not-exist-receipt-2"],
        )
    except KernelError as exc:
        assert "receipt=" in str(exc)
    else:
        raise AssertionError("dangling evidence_id must reject transition()")

    with kernel.connect() as conn:
        after = counts(conn)
        row = conn.execute(
            "SELECT receipt_id, outcome, payload FROM receipts "
            "ORDER BY receipt_seq DESC LIMIT 1"
        ).fetchone()
        receipt_id, outcome, receipt_payload_raw = row
        receipt_payload = json.loads(receipt_payload_raw)

        exc_row = conn.execute(
            "SELECT exception_id, receipt_id, payload FROM exceptions "
            "WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()

    delta = {k: after[k] - before[k] for k in before}
    assert delta == {
        "states": 0, "transitions": 0, "receipts": 1, "exceptions": 1,
        "authority_grants": 0, "authority_grant_revocations": 0,
        "evidence": 0, "receipt_evidence": 0, "identities": 0,
    }, f"no authoritative effects may survive a FAILED operation: {delta}"

    assert outcome == "FAILED"
    assert set(receipt_payload.keys()) == {"reason"}, (
        f"FAILED Receipt payload must be minimal (reason only), got: "
        f"{receipt_payload}"
    )
    assert "details" not in receipt_payload
    assert "error" not in json.dumps(receipt_payload)

    assert exc_row is not None, "Receipt and Exception must remain linked"
    assert exc_row[1] == receipt_id
    exception_payload = json.loads(exc_row[2])
    assert "details" in exception_payload
    assert "error" in exception_payload["details"]
    assert exception_payload["reason"] == receipt_payload["reason"]

    print("RECEIPT-2A (FAILED minimality + Exception linkage) passed")
    print(f"  receipt_payload:  {receipt_payload}")
    print(f"  exception_payload: {exception_payload}")

    # 3. Same check via a KernelError-classified FAILED-adjacent path is
    # unnecessary -- KernelError always yields REJECTED, never FAILED
    # (see transition()/grant()/etc.). Exercise the generic-Exception
    # branch too (not just sqlite3.IntegrityError) for full coverage of
    # both FAILED sources.

    real_get_state = kernel.get_state

    def boom(*args, **kwargs):
        raise RuntimeError("synthetic unexpected failure for RECEIPT-2B")

    kernel.get_state = boom
    try:
        try:
            kernel.transition(
                requester_identity_id=NATHAN,
                from_state_id=GENESIS,
                authority_grant_id=ROOT,
                new_state_payload={"probe": "receipt-2-minimality-b"},
            )
        except KernelError as exc:
            assert "receipt=" in str(exc)
        else:
            raise AssertionError("synthetic RuntimeError must reject transition()")
    finally:
        kernel.get_state = real_get_state

    with kernel.connect() as conn:
        row = conn.execute(
            "SELECT receipt_id, outcome, payload FROM receipts "
            "ORDER BY receipt_seq DESC LIMIT 1"
        ).fetchone()
        receipt_id_b, outcome_b, receipt_payload_raw_b = row
        receipt_payload_b = json.loads(receipt_payload_raw_b)
        exc_row_b = conn.execute(
            "SELECT payload FROM exceptions WHERE receipt_id = ?",
            (receipt_id_b,),
        ).fetchone()

    assert outcome_b == "FAILED"
    assert set(receipt_payload_b.keys()) == {"reason"}
    assert "RuntimeError" not in json.dumps(receipt_payload_b)
    exception_payload_b = json.loads(exc_row_b[0])
    assert exception_payload_b["details"]["exception_type"] == "RuntimeError"
    assert "synthetic unexpected failure" in exception_payload_b["details"]["error"]

    print("RECEIPT-2B (generic Exception branch, same minimality) passed")

    # 5/7. ACCEPTED and REJECTED behavior is unchanged.

    accepted = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=GENESIS,
        authority_grant_id=ROOT,
        new_state_payload={"probe": "receipt-2-accepted-unchanged"},
    )
    accepted_receipt = kernel.get_receipt(accepted["receipt_id"])
    assert accepted_receipt["outcome"] == "ACCEPTED"
    assert set(accepted_receipt["payload"].keys()) == {
        "from_state_id", "to_state_id", "authority_grant_id",
    }, "ACCEPTED Receipt payload shape must be unchanged"

    try:
        kernel.revoke(
            requester_identity_id="identity:clawde",
            authority_grant_id=ROOT,
            grant_id=ROOT,
        )
    except KernelError:
        pass
    else:
        raise AssertionError("non-root revoke attempt must be rejected")

    with kernel.connect() as conn:
        rejected_row = conn.execute(
            "SELECT outcome, payload FROM receipts ORDER BY receipt_seq DESC LIMIT 1"
        ).fetchone()
    assert rejected_row[0] == "REJECTED"
    rejected_payload = json.loads(rejected_row[1])
    assert set(rejected_payload.keys()) == {"reason"}, (
        "REJECTED Receipt payload shape must be unchanged (reason only, "
        "already minimal before this fix)"
    )

    print("RECEIPT-2C (ACCEPTED/REJECTED payload shapes unchanged) passed")

    # 6. Malformed Exception JSON is rejected structurally.

    with kernel.connect() as conn:
        try:
            conn.execute(
                "INSERT INTO exceptions (exception_id, receipt_id, created_at, payload) "
                "VALUES ('exception:malformed-receipt-2', ?, '2026-01-01T00:00:00Z', 'not-json{{{')",
                (receipt_id,),
            )
            conn.commit()
            raise AssertionError("malformed Exception JSON must be rejected")
        except sqlite3.IntegrityError as exc:
            assert "json_valid" in str(exc)

    print("RECEIPT-2D (Exception payload CHECK(json_valid) enforced) passed")

    print()
    print("RECEIPT-2A through 2D complete. All assertions passed.")
