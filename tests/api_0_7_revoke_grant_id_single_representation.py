"""EASTER-API-0 frozen-contract check: revoke's `grant_id` MCP argument has
exactly one HTTP representation -- the URL path -- so the HTTP layer can
never silently reinterpret it.

POST /v1/grants/{grant_id}/revoke used to accept a `grant_id` in the JSON
body as well and silently overwrote it with the path value, so a request
naming grant A in the body and grant B in the path revoked B without a word.
Now any body `grant_id` -- conflicting or identical -- is refused before MCP is
called, and the Kernel is provably untouched (revocation row count and the
target grant's validity are unchanged). A request with the grant identified by
the path alone still revokes normally.
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
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_api(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while True:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            if time.time() > deadline:
                raise
        time.sleep(0.1)


def post(port: int, path: str, payload: dict) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, body=json.dumps(payload), headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    return response.status, body


def count(db_path: Path, table: str) -> int:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="api-0-revoke-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        port = free_port()
        env = os.environ.copy()
        env.update({"KERNEL_DB_PATH": str(db_path), "API_PORT": str(port)})
        process = subprocess.Popen(
            [sys.executable, str(HERE / "api_server.py")], cwd=HERE, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_api(port)

            authority_id = "authority:api-0-revoke-test-op"
            status, body = post(
                port, "/v1/authorities",
                {"requester_identity_id": NATHAN, "authority_grant_id": ROOT, "authority_id": authority_id},
            )
            assert status == 200, (status, body)

            def issue() -> str:
                status, body = post(
                    port, "/v1/grants",
                    {
                        "requester_identity_id": NATHAN, "authority_grant_id": ROOT,
                        "identity_id": NATHAN, "authority_id": authority_id,
                    },
                )
                assert status == 200, (status, body)
                return body["grant_id"]

            target, decoy = issue(), issue()
            base = {"requester_identity_id": NATHAN, "authority_grant_id": ROOT}
            before = count(db_path, "authority_grant_revocations")

            # Conflicting: body names the decoy, path names the target.
            status, body = post(port, f"/v1/grants/{target}/revoke", {**base, "grant_id": decoy})
            assert status == 400 and "grant_id" in body["error"], (status, body)
            assert count(db_path, "authority_grant_revocations") == before, "conflicting body grant_id reached the Kernel"

            # Identical: still refused -- one representation, no comparison semantics.
            status, body = post(port, f"/v1/grants/{target}/revoke", {**base, "grant_id": target})
            assert status == 400 and "grant_id" in body["error"], (status, body)
            assert count(db_path, "authority_grant_revocations") == before, "duplicate body grant_id reached the Kernel"

            # Null is a representation too.
            status, body = post(port, f"/v1/grants/{target}/revoke", {**base, "grant_id": None})
            assert status == 400 and "grant_id" in body["error"], (status, body)
            assert count(db_path, "authority_grant_revocations") == before

            # Path alone: revokes exactly the path's grant, and only that one.
            status, body = post(port, f"/v1/grants/{target}/revoke", {**base, "reason": "api-0-revoke-test"})
            assert status == 200, (status, body)
            assert count(db_path, "authority_grant_revocations") == before + 1
            with sqlite3.connect(db_path) as conn:
                revoked = {row[0] for row in conn.execute("SELECT grant_id FROM authority_grant_revocations")}
            assert target in revoked and decoy not in revoked, (target, decoy, revoked)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    print("api_0_7_revoke_grant_id_single_representation: OK")
    print("  body grant_id (conflicting, identical, or null): 400 before MCP, Kernel untouched")
    print("  path-only revoke: revokes exactly the path's grant")


if __name__ == "__main__":
    main()
