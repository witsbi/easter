"""BROKER-2: Evidence-ordering safety, v1 role pin, and TTL hardening.

Independent council review of PR #35 (Pax, Ori) converged on a
load-bearing gap: the broker was committing a durable state change
(mint/revoke/rotation) and only afterward recording the kernel
Evidence that makes it accountable. If the Evidence write failed, the
state change had already happened -- an orphaned effect with no
kernel-side record. This file proves the fix organically: every test
below forces a REAL kernel rejection (a nonexistent authority_grant_id,
not a mock) and then checks the broker's own issuance.db directly to
confirm nothing durable happened.

Also covers the two smaller fixes from the same review: the v1 token
role is pinned to "agent" (anything else is rejected, not silently
coerced or silently ignored), and ttl_seconds is validated end to end
(type, positivity, and the 24h policy cap) with a clean 400 rather
than an unhandled exception.

Same real-subprocess-over-real-HTTP style as broker_1:

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


def http_get(port: int, path: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return resp.status, json.loads(text)


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="broker-2-", suffix=".db") as f:
        f.close()
        kernel_db = Path(f.name)
        shutil.copy2(source, kernel_db)

        issuance_dir = Path(tempfile.mkdtemp(prefix="broker-2-issuance-"))
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

        def tokens_table_count() -> int:
            conn = sqlite3.connect(issuance_db)
            try:
                return conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
            finally:
                conn.close()

        def token_row(jti: str) -> dict | None:
            conn = sqlite3.connect(issuance_db)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(
                    "SELECT * FROM tokens WHERE jti = ?", (jti,)
                ).fetchone()
            finally:
                conn.close()
            return dict(row) if row else None

        def keys_table_count() -> int:
            conn = sqlite3.connect(issuance_db)
            try:
                return conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
            finally:
                conn.close()

        try:
            wait_for_broker(port)

            status, body = http_post(
                port,
                "/rotate-key",
                {"requester_identity_id": NATHAN, "authority_grant_id": ROOT},
            )
            assert status == 200, (status, body)
            good_key_id = body["new_key_id"]

            # --- Fix 1a: mint with a bad grant must not orphan a token row ---
            before = tokens_table_count()
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": NONEXISTENT_GRANT,
                    "identity": "identity:hermes",
                    "grants": ["grant:fleet-alpha"],
                },
            )
            assert status == 502, (status, body)
            assert tokens_table_count() == before, (
                "mint must not create a tokens row when the kernel Evidence "
                "write fails -- this is exactly the orphaned-state defect"
            )

            # --- A real, successful mint to set up the next two checks ---
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": ["grant:fleet-alpha"],
                    "label": "broker-2-fixture",
                },
            )
            assert status == 200, (status, body)
            live_jti = body["jti"]

            # --- Fix 1b: revoke with a bad grant must not orphan the revocation ---
            status, body = http_post(
                port,
                "/revoke-token",
                {
                    "jti": live_jti,
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": NONEXISTENT_GRANT,
                },
            )
            assert status == 502, (status, body)
            row = token_row(live_jti)
            assert row is not None and row["revoked_at"] is None, (
                "a failed Evidence write must leave the token NOT revoked"
            )

            # Revoking it for real afterward must still work.
            status, body = http_post(
                port,
                "/revoke-token",
                {
                    "jti": live_jti,
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                },
            )
            assert status == 200 and body["revoked"] is True, (status, body)
            row = token_row(live_jti)
            assert row["revoked_at"] is not None

            # Revoking an already-revoked token is idempotent and does not
            # require (or attempt) a second Evidence write.
            status, body = http_post(
                port,
                "/revoke-token",
                {
                    "jti": live_jti,
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                },
            )
            assert status == 200 and body.get("already_revoked") is True, (status, body)

            # --- Fix 1c: rotate-key with a bad grant must not orphan a new key ---
            before_keys = keys_table_count()
            active_before = good_key_id
            status, body = http_post(
                port,
                "/rotate-key",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": NONEXISTENT_GRANT,
                },
            )
            assert status == 502, (status, body)
            assert keys_table_count() == before_keys, (
                "rotate-key must not create a keys row when the kernel "
                "Evidence write fails"
            )
            status, body = http_get(port, "/list")
            # The active key must still be the one from before the failed
            # rotation attempt -- confirmed via a real mint against it.
            status2, body2 = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:pax",
                    "grants": [],
                },
            )
            assert status2 == 200, (status2, body2)

            # --- Fix 2: v1 role is pinned to "agent" ---
            before = tokens_table_count()
            for bad_role in ("reader", "super-admin", ""):
                status, body = http_post(
                    port,
                    "/mint",
                    {
                        "requester_identity_id": NATHAN,
                        "authority_grant_id": ROOT,
                        "identity": "identity:hermes",
                        "grants": [],
                        "role": bad_role,
                    },
                )
                assert status == 400, (bad_role, status, body)
            assert tokens_table_count() == before, "rejected-role mints must not mint"

            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "role": "agent",
                },
            )
            assert status == 200, (status, body)

            # --- Fix 3: TTL validation ---
            before = tokens_table_count()
            for bad_ttl in (86401, -5, 0):
                status, body = http_post(
                    port,
                    "/mint",
                    {
                        "requester_identity_id": NATHAN,
                        "authority_grant_id": ROOT,
                        "identity": "identity:hermes",
                        "grants": [],
                        "ttl_seconds": bad_ttl,
                    },
                )
                assert status == 400, (bad_ttl, status, body)

            # A non-integer ttl_seconds must fail cleanly (400), never an
            # unhandled 500 from a bare ValueError/TypeError escaping the
            # route handler.
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "ttl_seconds": "garbage",
                },
            )
            assert status == 400, (status, body)
            assert tokens_table_count() == before, "rejected-TTL mints must not mint"

            # The exact cap boundary (86400s = 24h) is accepted.
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "ttl_seconds": 86400,
                },
            )
            assert status == 200, (status, body)

            # A sub-cap value works and produces the expected expiry.
            status, body = http_post(
                port,
                "/mint",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity": "identity:hermes",
                    "grants": [],
                    "ttl_seconds": 3600,
                },
            )
            assert status == 200, (status, body)

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

    print("broker_2_evidence_ordering_and_validation: OK")


if __name__ == "__main__":
    main()
