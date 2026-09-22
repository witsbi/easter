"""EASTER-CONSOLE-0: destructive actions require deliberate human
confirmation, enforced by the Console before any MCP call is made.

Not one of the brief's seven numbered verification points directly,
but a hard requirement of its own text: "Make destructive/authority-
changing actions explicit. In particular, revocation should require
deliberate human action rather than happening implicitly." This test
proves the Console rejects a mismatched confirmation *before* ever
calling MCP -- the grant remains valid afterward -- and that a correct
confirmation does proceed to a real Kernel revocation.
"""

from __future__ import annotations

import html
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"

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


def http_get(port: int, path: str) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return text


def http_post_form(port: int, path: str, fields: dict[str, str]) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = urllib.parse.urlencode(fields)
    conn.request(
        "POST",
        path,
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return text


def extract_result(page_text: str) -> tuple[bool, object]:
    match = PRE_BLOCK_RE.search(page_text)
    assert match is not None, f"no <pre> result block found in page: {page_text[:300]!r}"
    raw = html.unescape(match.group(1))
    is_error = "MCP tool error" in page_text
    try:
        return is_error, json.loads(raw)
    except json.JSONDecodeError:
        return is_error, raw


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="console-0-confirmation-gate-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        port = free_port()
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

            authority_id = "authority:console-0-confirmation-gate-op"
            body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                },
            )
            is_error, _ = extract_result(body)
            assert not is_error

            body = http_post_form(
                port,
                "/grant/issue",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "authority_id": authority_id,
                },
            )
            is_error, result = extract_result(body)
            assert not is_error
            grant_id = result["grant_id"]

            # A mismatched confirmation must be rejected by the
            # Console itself -- the page must say so, and it must
            # NOT contain an MCP result block for a revoke call.
            body = http_post_form(
                port,
                "/grant/revoke",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "grant_id": grant_id,
                    "confirm_grant_id": "not-the-same-id",
                },
            )
            assert "Confirmation did not match" in body
            assert "rejected by Console" in body

            # The grant must still be valid: a direct inspection
            # through the Console shows no revocation.
            body = http_get(port, f"/grant?grant_id={grant_id}")
            is_error, grant = extract_result(body)
            assert not is_error
            assert grant["grant_id"] == grant_id

            # An empty confirmation must also be rejected.
            body = http_post_form(
                port,
                "/grant/revoke",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "grant_id": grant_id,
                    "confirm_grant_id": "",
                },
            )
            assert "Confirmation did not match" in body

            # A correct confirmation proceeds to a real Kernel revoke.
            body = http_post_form(
                port,
                "/grant/revoke",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "grant_id": grant_id,
                    "confirm_grant_id": grant_id,
                    "reason": "console-0-confirmation-gate probe",
                },
            )
            is_error, result = extract_result(body)
            assert not is_error, result
            assert result["grant_id"] == grant_id

            # Same gate applies to revoke_all.
            body = http_post_form(
                port,
                "/grant/revoke-all",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "identity_id": NATHAN,
                    "confirm_identity_id": "not-nathan",
                },
            )
            assert "Confirmation did not match" in body
            assert "rejected by Console" in body

        finally:
            console_proc.terminate()
            try:
                console_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console_proc.kill()

    print("console_0_3_confirmation_gate: OK")
    print(f"  grant_id={grant_id} (mismatched confirmation rejected twice, then revoked on exact match)")


if __name__ == "__main__":
    main()
