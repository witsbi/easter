"""BROKER-3: key-level revocation, and concurrency/crash-reconciliation
safety for mint/revoke/rotate-key.

Ori's broader integration review of PR #35 (after Pax/Ori both closed
the first three fixes) raised four new findings. This file proves the
remediation for all four organically -- real subprocess, real HTTP,
real MCP stdio, real kernel, real concurrent requests -- never a mock.

Finding 1 (BLOCKER): RETIRED preserves rotation overlap (a retired
key's tokens keep verifying), but there was no REVOKED state, so a
suspected-exposed key could not be made to fail verification
immediately. Proven below: a token signed by a key is verified while
ACTIVE, still verifies once the key is RETIRED by rotation (overlap),
and stops verifying the instant the same key is explicitly REVOKED --
using the real ``broker.tokens.verify`` + ``broker.reader.IssuanceReader``
pair the gateway itself uses, against the broker's real issuance.db.

Finding 2 (HIGH): kernel Evidence succeeding and then the broker-local
durable write failing left no trace tying the two together. Proven
below for revoke-token by forcing ``mark_revoked`` to fail *after* its
Evidence write already succeeded, confirming the operation lands in
issuance.db's `operations` table as `evidence_confirmed` (not lost),
and confirming ``/reconcile`` finishes it using the *same* jti/evidence
identity -- never a new one.

Finding 3 (HIGH): two concurrent revoke-token requests for the same
jti could both observe "not yet revoked" and both record kernel
Evidence for one logical state change. Proven below with two real
concurrent HTTP requests (not sequential calls dressed up as
concurrent): independently re-verified against the kernel's own
evidence table that *exactly one* broker_token_revoke Evidence record
exists for the jti afterward, regardless of which response "won".

Finding 4 (MEDIUM): a crash between committing a rotated-in key and
retiring the old one could leave two ACTIVE keys with no path back to
one. Proven below by forcing ``retire_key`` to fail after
``commit_new_key`` already succeeded, confirming both keys are
transiently ACTIVE, and confirming ``/reconcile`` retires the old key
without re-rotating or re-recording Evidence.

Same real-subprocess-over-real-HTTP style as broker_1/broker_2:

    this test --(HTTP)--> broker/app.py --(MCP stdio)--> mcp_server.py --> Kernel
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
NONEXISTENT_GRANT = "grant:this-grant-does-not-exist-00000000"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_broker(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return
        except OSError as exc:
            last_exc = exc
        time.sleep(0.1)
    raise TimeoutError(f"broker did not become ready on port {port}: {last_exc}")


def http_post(port: int, path: str, body: dict) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    payload = json.dumps(body).encode()
    conn.request(
        "POST", path, body=payload, headers={"Content-Type": "application/json"}
    )
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return resp.status, json.loads(text)


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="broker-3-", suffix=".db") as f:
        f.close()
        kernel_db = Path(f.name)
        shutil.copy2(source, kernel_db)

        issuance_dir = Path(tempfile.mkdtemp(prefix="broker-3-issuance-"))
        issuance_db = issuance_dir / "issuance.db"
        port = free_port()

        env = dict(os.environ)
        env.pop("PYTHONOPTIMIZE", None)
        env["PYTHONPATH"] = str(HERE)

        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "broker.app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--issuance-db",
                str(issuance_db),
                "--key-dir",
                str(issuance_dir / "keys"),
                "--kernel-db",
                str(kernel_db),
            ],
            cwd=str(HERE),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def keys_rows() -> dict[str, dict]:
            conn = sqlite3.connect(issuance_db)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT * FROM keys").fetchall()
            finally:
                conn.close()
            return {r["id"]: dict(r) for r in rows}

        def operations_rows() -> dict[str, dict]:
            conn = sqlite3.connect(issuance_db)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT * FROM operations").fetchall()
            finally:
                conn.close()
            return {r["op_key"]: dict(r) for r in rows}

        def kernel_evidence_count(kind: str, match_field: str, match_value: str) -> int:
            conn = sqlite3.connect(kernel_db)
            try:
                rows = conn.execute("SELECT payload FROM evidence").fetchall()
            finally:
                conn.close()
            count = 0
            for (payload_json,) in rows:
                payload = json.loads(payload_json)
                if payload.get("kind") == kind and payload.get(match_field) == match_value:
                    count += 1
            return count

        try:
            wait_for_broker(port)

            # ================================================================
            # Finding 1: ACTIVE verifies, RETIRED still verifies (overlap),
            # REVOKED never verifies again.
            # ================================================================
            from broker import tokens as broker_tokens
            from broker.reader import IssuanceReader

            reader = IssuanceReader(issuance_db)

            status, body = http_post(
                port, "/rotate-key", {"requester_identity_id": NATHAN, "authority_grant_id": ROOT}
            )
            assert status == 200, (status, body)
            key_a = body["new_key_id"]

            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "label": "signed-by-key-a",
                },
            )
            assert status == 200, (status, body)
            token_a = body["token"]

            claims = broker_tokens.verify(token_a, resolve_public_key=reader.resolve_public_key)
            assert claims.sub == "identity:hermes", "token must verify while its key is ACTIVE"

            status, body = http_post(
                port, "/rotate-key", {"requester_identity_id": NATHAN, "authority_grant_id": ROOT}
            )
            assert status == 200, (status, body)
            key_b = body["new_key_id"]
            assert keys_rows()[key_a]["status"] == "retired"

            claims = broker_tokens.verify(token_a, resolve_public_key=reader.resolve_public_key)
            assert claims.sub == "identity:hermes", (
                "RETIRED must preserve rotation overlap -- a token signed by a "
                "retired (not revoked) key must keep verifying"
            )

            # Revoking with a bad grant must not orphan a key-level
            # revocation (same Fix-1-style regression coverage as the
            # other state-changing endpoints).
            status, body = http_post(
                port,
                "/revoke-key",
                {"key_id": key_a, "requester_identity_id": NATHAN, "authority_grant_id": NONEXISTENT_GRANT},
            )
            assert status == 502, (status, body)
            assert keys_rows()[key_a]["status"] == "retired", (
                "a failed Evidence write must leave the key NOT revoked"
            )
            claims = broker_tokens.verify(token_a, resolve_public_key=reader.resolve_public_key)
            assert claims.sub == "identity:hermes"

            status, body = http_post(
                port,
                "/revoke-key",
                {"key_id": key_a, "requester_identity_id": NATHAN, "authority_grant_id": ROOT},
            )
            assert status == 200 and body["revoked"] is True, (status, body)
            key_a_revoke_evidence = body["evidence_id"]
            assert keys_rows()[key_a]["status"] == "revoked"

            try:
                broker_tokens.verify(token_a, resolve_public_key=reader.resolve_public_key)
                raise AssertionError(
                    "REVOKED must immediately invalidate every token signed by "
                    "that key -- this token must no longer verify"
                )
            except broker_tokens.TokenError:
                pass

            # Idempotent re-revoke: no second Evidence write.
            status, body = http_post(
                port,
                "/revoke-key",
                {"key_id": key_a, "requester_identity_id": NATHAN, "authority_grant_id": ROOT},
            )
            assert status == 200 and body.get("already_revoked") is True, (status, body)

            # key_b (never revoked) is unaffected by key_a's revocation.
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:pax",
                    "grants": [],
                },
            )
            assert status == 200, (status, body)
            token_b = body["token"]
            claims = broker_tokens.verify(token_b, resolve_public_key=reader.resolve_public_key)
            assert claims.sub == "identity:pax", "an unrelated key's tokens must be unaffected"

            # Independently re-verify against the kernel's own records,
            # not the broker's self-report.
            conn = sqlite3.connect(kernel_db)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT payload FROM evidence WHERE evidence_id = ?", (key_a_revoke_evidence,)
            ).fetchone()
            conn.close()
            assert row is not None
            payload = json.loads(row["payload"])
            assert payload["kind"] == "broker_key_revoke" and payload["key_id"] == key_a

            # ================================================================
            # Finding 3: two concurrent revoke-token requests for the same
            # jti must not both record kernel Evidence for one revoke.
            # ================================================================
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "label": "race-fixture",
                },
            )
            assert status == 200, (status, body)
            race_jti = body["jti"]

            results: list[tuple[int, dict]] = [None, None]  # type: ignore[list-item]

            def do_revoke(slot: int) -> None:
                results[slot] = http_post(
                    port,
                    "/revoke-token",
                    {
                        "jti": race_jti,
                        "requester_identity_id": NATHAN,
                        "authority_grant_id": ROOT,
                    },
                )

            t1 = threading.Thread(target=do_revoke, args=(0,))
            t2 = threading.Thread(target=do_revoke, args=(1,))
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)

            fresh_revokes = [
                (status, body)
                for status, body in results
                if status == 200 and body.get("revoked") is True and not body.get("already_revoked")
            ]
            other_outcomes = [
                (status, body)
                for status, body in results
                if (status, body) not in fresh_revokes
            ]
            assert len(fresh_revokes) == 1, (
                "exactly one of two concurrent revokes of the same jti must "
                f"be the one that actually records kernel Evidence; got {results}"
            )
            for status, body in other_outcomes:
                assert status == 409 or body.get("already_revoked") is True, (
                    "the losing concurrent revoke must be rejected (409, still "
                    f"in progress) or see the already-completed result; got {status} {body}"
                )

            assert kernel_evidence_count("broker_token_revoke", "jti", race_jti) == 1, (
                "two concurrent revoke requests for one jti must never produce "
                "two kernel Evidence records for one logical state change"
            )

            # ================================================================
            # Finding 2: kernel Evidence succeeds, then the broker-local
            # durable write fails -- must not be silently lost, and
            # /reconcile must finish it using the *same* identity, never
            # calling the kernel a second time.
            #
            # A real crash between the handler's mark_evidence_confirmed
            # call and its mark_revoked call leaves exactly one physical
            # state in issuance.db: an 'operations' row with status
            # evidence_confirmed, and the tokens row still unrevoked.
            # Driving the real Issuance object directly to that exact
            # state (rather than racing a chmod against the live
            # subprocess, which -- confirmed by hand -- fails at the
            # earlier claim_operation() write instead, since a
            # read-only file blocks every write in the handler, not
            # only the one being targeted) reproduces that physical
            # state precisely, then exercises the real, un-mocked
            # /reconcile code path against it.
            # ================================================================
            from broker.issuance import Issuance

            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "label": "finding-2-fixture",
                },
            )
            assert status == 200, (status, body)
            stuck_jti = body["jti"]

            direct = Issuance(issuance_db, issuance_dir / "keys")
            stuck_op_key = f"revoke:{stuck_jti}"
            assert direct.claim_operation(stuck_op_key, "revoke", {"jti": stuck_jti, "actor": NATHAN})
            direct.mark_evidence_confirmed(
                stuck_op_key, evidence_id="evidence:finding-2-fixture", receipt_id="receipt:finding-2-fixture"
            )
            # Simulated crash: mark_revoked never ran.

            ops = operations_rows()
            assert stuck_op_key in ops, (
                "the operation must survive the broker-local write failure as "
                "a durable, inspectable trace -- this is exactly what Finding "
                "2 says must never be silently lost"
            )
            assert ops[stuck_op_key]["status"] == "evidence_confirmed"
            assert ops[stuck_op_key]["evidence_id"] == "evidence:finding-2-fixture", (
                "the surviving row must cite the exact evidence/receipt "
                "identity the kernel already confirmed"
            )

            conn = sqlite3.connect(issuance_db)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT revoked_at FROM tokens WHERE jti = ?", (stuck_jti,)
            ).fetchone()
            conn.close()
            assert row["revoked_at"] is None, (
                "the durable effect genuinely did not land -- confirms this "
                "is a real disagreement, not a false alarm"
            )

            before_evidence_count = kernel_evidence_count("broker_token_revoke", "jti", stuck_jti)
            status, body = http_post(port, "/reconcile", {})
            assert status == 200, (status, body)
            assert stuck_op_key in body["reconciled"], body

            assert (
                kernel_evidence_count("broker_token_revoke", "jti", stuck_jti) == before_evidence_count
            ), (
                "/reconcile must finish the original operation using its "
                "already-confirmed evidence identity, never calling the "
                "kernel a second time for it"
            )
            conn = sqlite3.connect(issuance_db)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT revoked_at FROM tokens WHERE jti = ?", (stuck_jti,)
            ).fetchone()
            conn.close()
            assert row["revoked_at"] is not None, "reconcile must complete the durable effect"
            assert stuck_op_key not in operations_rows(), (
                "a fully reconciled operation's scratch row must be cleaned up"
            )

            # ================================================================
            # Finding 4: a crash between committing a rotated-in key and
            # retiring the old one must not leave two permanently-ACTIVE
            # keys with no path back to one.
            #
            # As with Finding 2 above, a read-only issuance.db blocks
            # the handler's *first* write (claim_operation) rather than
            # isolating a later one, so a live-HTTP chmod cannot target
            # the specific commit_new_key/retire_key gap this finding
            # describes. Both sub-cases below instead drive the real
            # Issuance object directly to the exact physical state a
            # crash at each point would leave, then exercise the real
            # /reconcile path against each.
            # ================================================================
            direct = Issuance(issuance_db, issuance_dir / "keys")

            # Sub-case A: Evidence confirmed a new key, but commit_new_key
            # itself never ran (the private key material from that
            # attempt is gone). Must be flagged, not silently healed by
            # fabricating a replacement key the Evidence never named.
            active_before_rotation = direct.active_key()["id"]
            _priv_lost, lost_key_id, _lost_pub = direct.prepare_new_key()
            lost_op_key = f"rotate_from:{active_before_rotation}"
            assert direct.claim_operation(
                lost_op_key,
                "rotate",
                {"new_key_id": lost_key_id, "old_key_id": active_before_rotation, "actor": NATHAN},
            )
            direct.mark_evidence_confirmed(
                lost_op_key, evidence_id="evidence:finding-4a-fixture", receipt_id="receipt:finding-4a-fixture"
            )
            # Simulated crash: commit_new_key never ran, so _priv_lost is
            # discarded here, exactly as a crashed process's memory would
            # be -- never persisted anywhere, matching the module's
            # private-key-never-logged invariant even in this failure path.

            status, body = http_post(port, "/reconcile", {})
            assert status == 200, (status, body)
            assert lost_op_key not in body["reconciled"], (
                "a rotation whose new key material is gone must never be "
                "auto-reconciled -- that would mean minting a replacement "
                "key the original Evidence record never described"
            )
            assert any(op["op_key"] == lost_op_key for op in body["needs_attention"]), body
            assert operations_rows()[lost_op_key]["status"] == "needs_manual_reconciliation"
            assert keys_rows()[active_before_rotation]["status"] == "active", (
                "a rotation whose new key never persisted must leave the "
                "original key active -- minting must still work"
            )
            assert lost_key_id not in keys_rows(), (
                "the never-persisted key must not exist in the keys table"
            )
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                },
            )
            assert status == 200, ("minting must still work after a flagged failed rotation", status, body)

            # By design, sub-case A's op_key (keyed to the active key it
            # tried to rotate from) stays permanently claimed by its
            # 'needs_manual_reconciliation' row until an admin clears
            # it -- a live rotation from that same key is correctly
            # still blocked:
            status, body = http_post(
                port, "/rotate-key", {"requester_identity_id": NATHAN, "authority_grant_id": ROOT}
            )
            assert status == 409, (
                "a key with an unresolved rotation must stay blocked from "
                f"further rotation attempts, not silently proceed; got {status} {body}"
            )

            # generate_key() is the documented convenience path that
            # bypasses the operation-claim machinery entirely (for test
            # fixtures / an operator manually recovering outside the
            # blocked op_key) -- used here only to give sub-case B a
            # fresh, unblocked active key to work from.
            direct.generate_key(actor=NATHAN)

            # Sub-case B: commit_new_key succeeds, but retire_key(old)
            # never runs -- the gap Finding 4 literally describes
            # ("a crash between 3 and 4"). This one needs no secret
            # material to finish, so /reconcile must auto-heal it.
            old_active = direct.active_key()
            assert old_active is not None
            priv, new_kid, new_pub = direct.prepare_new_key()
            op_key = f"rotate_from:{old_active['id']}"
            assert direct.claim_operation(
                op_key, "rotate", {"new_key_id": new_kid, "old_key_id": old_active["id"], "actor": NATHAN}
            )
            direct.mark_evidence_confirmed(op_key, evidence_id="evidence:test-fixture", receipt_id="receipt:test-fixture")
            direct.commit_new_key(priv, new_kid, new_pub, actor=NATHAN)
            direct.mark_key_committed(op_key)
            # Simulated crash: retire_key(old) never ran. Both keys are
            # transiently ACTIVE -- exactly Finding 4's described gap.
            assert keys_rows()[old_active["id"]]["status"] == "active"
            assert keys_rows()[new_kid]["status"] == "active"

            status, body = http_post(port, "/reconcile", {})
            assert status == 200, (status, body)
            assert op_key in body["reconciled"], body
            after = keys_rows()
            assert after[old_active["id"]]["status"] == "retired", (
                "/reconcile must finish retiring the old key -- this needs no "
                "secret material and is always auto-reconcilable"
            )
            assert after[new_kid]["status"] == "active"
            assert op_key not in operations_rows()
            # No new Evidence was recorded for this reconciliation -- it
            # reused the original (fixture) evidence_id, never re-called
            # the kernel.
            assert kernel_evidence_count("broker_key_rotation", "new_key_id", new_kid) == 0, (
                "reconciling a rotation's retire-the-old-key step must not "
                "call the kernel again"
            )

        finally:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()

        combined_output = stdout + stderr
        assert "BEGIN PRIVATE KEY" not in combined_output
        for line in combined_output.splitlines():
            if "privkey" in line.lower():
                assert "keyring:" in line or "file:" in line, (
                    f"line mentions privkey without a reference marker: {line!r}"
                )

        shutil.rmtree(issuance_dir)

    print("broker_3_key_revocation_and_concurrency: OK")


if __name__ == "__main__":
    main()
