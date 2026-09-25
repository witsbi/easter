"""EASTER-API-0 independent-review remediation: an untrusted/cross-origin
state-changing request is rejected before MCP is ever invoked, on every
one of the six write routes (record_evidence, transition,
define_authority, grant, revoke, revoke_all) -- not just the four the
Console happens to expose.

Binding to loopback alone does not stop a malicious cross-origin page
from submitting a matching request to this API on the operator's
behalf. Worse than the Console's case: a JSON POST with
Content-Type: application/json would be preflighted by a real browser
(and could be blocked there), but Content-Type: text/plain is one of
the three CORS-safelisted "simple" content types, so a browser never
sends a preflight for it at all -- and Starlette's Request.json() does
not consult Content-Type, so such a request parses identically to a
normal application/json body once it arrives. This test proves
api_server.reject_cross_origin blocks both the ordinary cross-origin
case and this non-preflighted case, on all six routes, and does not
block legitimate same-origin/no-origin (first-party) use.

"Rejected before MCP is invoked" is proven behaviorally, not just by
response status: for each route, a direct sqlite count of the affected
table is taken immediately before and after the cross-origin attempt.
An unchanged count means the Kernel was never touched.

revoke_all is deliberately never executed to success in this script
(only its rejection path is proven) -- a real revoke_all against
NATHAN would revoke the same root grant every other case here still
needs.
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
GENESIS = "state:genesis"
EVIL_ORIGIN = "http://evil.example"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_api(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as resp:
                if resp.status == 200 and json.loads(resp.read())["status"] == "ok":
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_exc = exc
        time.sleep(0.1)
    raise TimeoutError(f"API did not become ready on port {port}: {last_exc}")


def http_post(port: int, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, object]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    text = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(text)
    except json.JSONDecodeError:
        return resp.status, text.decode()


def post_json(port: int, path: str, payload: dict, extra_headers: dict[str, str] | None = None) -> tuple[int, object]:
    """A request shaped like a normal, would-be-preflighted JSON POST."""
    headers = {"Content-Type": "application/json"}
    headers.update(extra_headers or {})
    return http_post(port, path, json.dumps(payload).encode(), headers)


def post_json_non_preflighted(port: int, path: str, payload: dict, origin: str) -> tuple[int, object]:
    """A cross-origin request a real browser never preflights.

    Content-Type: text/plain is one of the three CORS-safelisted
    "simple" request content types (alongside
    application/x-www-form-urlencoded and multipart/form-data): a
    browser sends this straight to the wire with no OPTIONS
    preflight, Origin attached, exactly as if a hidden
    <form enctype="text/plain"> on an attacker's page had auto-submitted
    with a body engineered to be valid JSON. Starlette's
    Request.json() does not check Content-Type, so this parses
    identically to an ordinary application/json body once it lands --
    the only thing standing between it and the Kernel is
    reject_cross_origin's Origin check.
    """
    return http_post(
        port,
        path,
        json.dumps(payload).encode(),
        {"Content-Type": "text/plain", "Origin": origin},
    )


def table_count(db_path: Path, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="api-0-csrf-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        port = free_port()
        api_origin = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.update({"KERNEL_DB_PATH": str(db_path), "API_PORT": str(port)})
        process = subprocess.Popen([sys.executable, str(HERE / "api_server.py")], cwd=HERE, env=env)
        try:
            wait_for_api(port)

            # ---------------------------------------------------
            # /v1/authorities -> define_authority
            # ---------------------------------------------------
            authority_1 = "authority:api-0-csrf-test-op"
            authority_2 = "authority:api-0-csrf-test-op-2"
            before = table_count(db_path, "authorities")

            define_body = {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "authority_id": authority_1,
            }
            status, body = post_json(port, "/v1/authorities", define_body, {"Origin": EVIL_ORIGIN})
            assert status == 403, (status, body)
            assert table_count(db_path, "authorities") == before, "cross-origin define_authority reached the Kernel"

            status, body = post_json_non_preflighted(port, "/v1/authorities", define_body, EVIL_ORIGIN)
            assert status == 403, (status, body)
            assert table_count(db_path, "authorities") == before, (
                "non-preflighted cross-origin define_authority reached the Kernel"
            )

            status, body = post_json(port, "/v1/authorities", define_body, {"Referer": EVIL_ORIGIN + "/some/page"})
            assert status == 403, (status, body)
            assert table_count(db_path, "authorities") == before, "cross-origin Referer must also be rejected"

            status, body = post_json(
                port,
                "/v1/authorities",
                define_body,
                {"Referer": f"{api_origin}.evil.example/attacker"},
            )
            assert status == 403, (status, body)
            assert table_count(db_path, "authorities") == before, "lookalike Referer host must be rejected"

            status, body = post_json(port, "/v1/authorities", define_body)
            assert status == 200, (status, body)
            assert body["authority_id"] == authority_1
            assert table_count(db_path, "authorities") == before + 1

            status, body = post_json(
                port,
                "/v1/authorities",
                {**define_body, "authority_id": authority_2},
                {"Origin": api_origin},
            )
            assert status == 200, (status, body)
            assert table_count(db_path, "authorities") == before + 2

            # ---------------------------------------------------
            # /v1/evidence -> record_evidence
            # ---------------------------------------------------
            before = table_count(db_path, "evidence")
            evidence_body = {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "payload": {"probe": "api-0-csrf-test"},
            }
            status, body = post_json(port, "/v1/evidence", evidence_body, {"Origin": EVIL_ORIGIN})
            assert status == 403, (status, body)
            assert table_count(db_path, "evidence") == before, "cross-origin record_evidence reached the Kernel"

            status, body = post_json_non_preflighted(port, "/v1/evidence", evidence_body, EVIL_ORIGIN)
            assert status == 403, (status, body)
            assert table_count(db_path, "evidence") == before, (
                "non-preflighted cross-origin record_evidence reached the Kernel"
            )

            status, body = post_json(port, "/v1/evidence", evidence_body)
            assert status == 200, (status, body)
            evidence_id = body["evidence_id"]
            assert evidence_id.startswith("evidence:")
            assert table_count(db_path, "evidence") == before + 1

            # ---------------------------------------------------
            # /v1/grants -> grant
            # ---------------------------------------------------
            before = table_count(db_path, "authority_grants")
            grant_body = {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "identity_id": NATHAN,
                "authority_id": authority_1,
            }
            status, body = post_json(port, "/v1/grants", grant_body, {"Origin": EVIL_ORIGIN})
            assert status == 403, (status, body)
            assert table_count(db_path, "authority_grants") == before, "cross-origin grant reached the Kernel"

            status, body = post_json_non_preflighted(port, "/v1/grants", grant_body, EVIL_ORIGIN)
            assert status == 403, (status, body)
            assert table_count(db_path, "authority_grants") == before, (
                "non-preflighted cross-origin grant reached the Kernel"
            )

            status, body = post_json(port, "/v1/grants", grant_body)
            assert status == 200, (status, body)
            grant_id = body["grant_id"]
            assert table_count(db_path, "authority_grants") == before + 1

            # ---------------------------------------------------
            # /v1/grants/{grant_id}/revoke -> revoke
            # ---------------------------------------------------
            before = table_count(db_path, "authority_grant_revocations")
            revoke_body = {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "reason": "api-0-csrf-test cross-origin attempt",
            }
            status, body = post_json(port, f"/v1/grants/{grant_id}/revoke", revoke_body, {"Origin": EVIL_ORIGIN})
            assert status == 403, (status, body)
            assert table_count(db_path, "authority_grant_revocations") == before, (
                "cross-origin revoke reached the Kernel"
            )

            status, body = post_json_non_preflighted(port, f"/v1/grants/{grant_id}/revoke", revoke_body, EVIL_ORIGIN)
            assert status == 403, (status, body)
            assert table_count(db_path, "authority_grant_revocations") == before, (
                "non-preflighted cross-origin revoke reached the Kernel"
            )

            status, body = post_json(
                port,
                f"/v1/grants/{grant_id}/revoke",
                {**revoke_body, "reason": "api-0-csrf-test legit revoke"},
            )
            assert status == 200, (status, body)
            assert table_count(db_path, "authority_grant_revocations") == before + 1

            # ---------------------------------------------------
            # /v1/transitions -> transition
            # ---------------------------------------------------
            before = table_count(db_path, "transitions")
            transition_body = {
                "requester_identity_id": NATHAN,
                "from_state_id": GENESIS,
                "authority_grant_id": ROOT,
                "new_state_payload": {"probe": "api-0-csrf-test"},
                "evidence_ids": [evidence_id],
            }
            status, body = post_json(port, "/v1/transitions", transition_body, {"Origin": EVIL_ORIGIN})
            assert status == 403, (status, body)
            assert table_count(db_path, "transitions") == before, "cross-origin transition reached the Kernel"

            status, body = post_json_non_preflighted(port, "/v1/transitions", transition_body, EVIL_ORIGIN)
            assert status == 403, (status, body)
            assert table_count(db_path, "transitions") == before, (
                "non-preflighted cross-origin transition reached the Kernel"
            )

            status, body = post_json(port, "/v1/transitions", transition_body)
            assert status == 200, (status, body)
            assert table_count(db_path, "transitions") == before + 1

            # ---------------------------------------------------
            # /v1/grants/revoke-all -> revoke_all (rejection-only:
            # never actually executed, see module docstring)
            # ---------------------------------------------------
            before = table_count(db_path, "authority_grant_revocations")
            revoke_all_body = {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "identity_id": NATHAN,
            }
            status, body = post_json(port, "/v1/grants/revoke-all", revoke_all_body, {"Origin": EVIL_ORIGIN})
            assert status == 403, (status, body)
            assert table_count(db_path, "authority_grant_revocations") == before, (
                "cross-origin revoke_all reached the Kernel"
            )

            status, body = post_json_non_preflighted(port, "/v1/grants/revoke-all", revoke_all_body, EVIL_ORIGIN)
            assert status == 403, (status, body)
            assert table_count(db_path, "authority_grant_revocations") == before, (
                "non-preflighted cross-origin revoke_all reached the Kernel"
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    print("api_0_2_csrf_origin_protection: OK")
    print("  cross-origin Origin header: rejected (403) before MCP, on all 6 state-changing routes")
    print("  non-preflighted cross-origin (Content-Type: text/plain): rejected (403) before MCP, same 6 routes")
    print("  cross-origin Referer header: rejected (403) before MCP")
    print("  first-party (no Origin/Referer) and legit same-origin requests: succeed unaffected")


if __name__ == "__main__":
    main()
