"""EASTER-CONSOLE-0, PR #13 review fix 1: an untrusted/cross-origin
authority-changing request is rejected before MCP is ever invoked.

The typed re-confirmation fields on revoke/revoke_all guard against an
operator's own mistake -- they do nothing to stop a malicious
cross-origin page from submitting a matching hidden form to this
Console on the operator's behalf (it can just fill in the same value
twice). This test proves the separate Origin/Referer check
(console.reject_cross_origin) actually blocks that attack, for all
four authority-changing routes, and does not block legitimate
same-origin/no-origin (first-party tooling) use.

"Rejected before MCP is invoked" is proven behaviorally, not just by
response text: for each route, a direct sqlite count of the affected
table is taken immediately before and after the cross-origin attempt.
An unchanged count means the Kernel was never touched.
"""

from __future__ import annotations

import html
import http.client
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
EVIL_ORIGIN = "http://evil.example"

PRE_BLOCK_RE = re.compile(r"<pre>(.*?)</pre>", re.DOTALL)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_console(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return
        except OSError as exc:
            last_exc = exc
        time.sleep(0.1)
    raise TimeoutError(f"console did not become ready on port {port}: {last_exc}")


def http_post_form(port: int, path: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = urllib.parse.urlencode(fields)
    full_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    full_headers.update(headers or {})
    conn.request("POST", path, body=body, headers=full_headers)
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return resp.status, text


def extract_result(page_text: str) -> tuple[bool, object]:
    match = PRE_BLOCK_RE.search(page_text)
    assert match is not None, f"no <pre> result block found: {page_text[:300]!r}"
    raw = html.unescape(match.group(1))
    is_error = "MCP tool error" in page_text
    try:
        return is_error, json.loads(raw)
    except json.JSONDecodeError:
        return is_error, raw


def table_count(db_path: Path, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="console-0-csrf-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        port = free_port()
        console_origin = f"http://127.0.0.1:{port}"
        env = dict(os.environ)
        env["KERNEL_DB_PATH"] = str(db_path)
        env["CONSOLE_HOST"] = "127.0.0.1"
        env["CONSOLE_PORT"] = str(port)

        console_proc = subprocess.Popen(
            [sys.executable, str(HERE / "console.py")],
            cwd=str(HERE),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_console(port)

            # --- /authority/define: cross-origin Origin header ---
            authority_id = "authority:console-0-csrf-test-op"
            before = table_count(db_path, "authorities")
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                },
                headers={"Origin": EVIL_ORIGIN},
            )
            assert status == 403, (status, body[:300])
            assert "Rejected" in body and "cross-origin" in body
            after = table_count(db_path, "authorities")
            assert after == before, "cross-origin define_authority must never reach the Kernel"

            # Same request, mismatched Referer instead of Origin -- also rejected.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                },
                headers={"Referer": EVIL_ORIGIN + "/some/page"},
            )
            assert status == 403, (status, body[:300])
            after = table_count(db_path, "authorities")
            assert after == before, "cross-origin Referer must also be rejected before the Kernel"

            # Legit (no Origin/Referer -- first-party tooling) request succeeds,
            # proving the guard blocks the attack without blocking real use.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                },
            )
            assert status == 200, (status, body[:300])
            is_error, result = extract_result(body)
            assert not is_error, result
            after = table_count(db_path, "authorities")
            assert after == before + 1

            # Legit same-origin request (real Origin header matching the Console) also succeeds.
            other_authority_id = "authority:console-0-csrf-test-op-2"
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": other_authority_id,
                },
                headers={"Origin": console_origin},
            )
            assert status == 200, (status, body[:300])
            is_error, result = extract_result(body)
            assert not is_error, result

            # --- /grant/issue: cross-origin ---
            before = table_count(db_path, "authority_grants")
            status, body = http_post_form(
                port,
                "/grant/issue",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "authority_id": authority_id,
                },
                headers={"Origin": EVIL_ORIGIN},
            )
            assert status == 403, (status, body[:300])
            after = table_count(db_path, "authority_grants")
            assert after == before, "cross-origin grant issuance must never reach the Kernel"

            status, body = http_post_form(
                port,
                "/grant/issue",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "authority_id": authority_id,
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            grant_id = result["grant_id"]
            after = table_count(db_path, "authority_grants")
            assert after == before + 1

            # --- /grant/revoke: cross-origin ---
            before_rev = table_count(db_path, "authority_grant_revocations")
            status, body = http_post_form(
                port,
                "/grant/revoke",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "grant_id": grant_id,
                    "confirm_grant_id": grant_id,
                    "reason": "csrf-test cross-origin attempt",
                },
                headers={"Origin": EVIL_ORIGIN},
            )
            assert status == 403, (status, body[:300])
            after_rev = table_count(db_path, "authority_grant_revocations")
            assert after_rev == before_rev, (
                "cross-origin revoke must never reach the Kernel, even with a "
                "correctly-matching typed confirmation"
            )

            status, body = http_post_form(
                port,
                "/grant/revoke",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "grant_id": grant_id,
                    "confirm_grant_id": grant_id,
                    "reason": "csrf-test legit revoke",
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result
            after_rev = table_count(db_path, "authority_grant_revocations")
            assert after_rev == before_rev + 1

            # --- /grant/revoke-all: cross-origin ---
            status, body = http_post_form(
                port,
                "/grant/issue",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "authority_id": other_authority_id,
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result

            before_rev = table_count(db_path, "authority_grant_revocations")
            status, body = http_post_form(
                port,
                "/grant/revoke-all",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "confirm_identity_id": NATHAN,
                },
                headers={"Origin": EVIL_ORIGIN},
            )
            assert status == 403, (status, body[:300])
            after_rev = table_count(db_path, "authority_grant_revocations")
            assert after_rev == before_rev, "cross-origin revoke_all must never reach the Kernel"

        finally:
            console_proc.terminate()
            try:
                console_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console_proc.kill()

    print("console_0_5_csrf_origin_protection: OK")
    print("  cross-origin Origin header: rejected (403) before MCP, on all 4 authority-changing routes")
    print("  cross-origin Referer header: rejected (403) before MCP")
    print("  first-party (no Origin/Referer) and legit same-origin requests: succeed unaffected")


if __name__ == "__main__":
    main()
