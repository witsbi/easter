"""EASTER-CONSOLE-0, PR #13 review fix 2: malformed JSON in a free-text
payload field renders an actionable form validation error, not an
HTTP 500.

/authority/define's optional `payload` field is free text the operator
types as JSON. Before this fix, an invalid value (e.g. "{bad json")
propagated an uncaught json.JSONDecodeError out of the route handler,
which Starlette turns into a bare HTTP 500 with no useful message.
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


def http_post_form(port: int, path: str, fields: dict[str, str]) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = urllib.parse.urlencode(fields)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
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
    with tempfile.NamedTemporaryFile(prefix="console-0-malformed-json-", suffix=".db") as f:
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

            authority_id = "authority:console-0-malformed-json-op"
            before = table_count(db_path, "authorities")

            # Malformed JSON in the free-text payload field.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                    "payload": "{bad json",
                },
            )
            assert status == 400, f"expected 400 form-validation error, got {status}: {body[:500]!r}"
            assert "Invalid JSON in payload field" in body
            assert "<form" in body, "the form must be re-rendered so the operator can fix and resubmit"

            after = table_count(db_path, "authorities")
            assert after == before, "malformed payload must never reach the Kernel"

            # A second malformed value, this time a JSON array where the
            # tool expects an object (valid JSON, wrong shape) -- MCP-0's
            # own type validation should reject it as a normal tool error,
            # not a Console-side crash.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                    "payload": "[1, 2, 3]",
                },
            )
            assert status in (200, 400), f"must not be a bare 500, got {status}: {body[:500]!r}"

            # Fixing the payload and resubmitting succeeds normally.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                    "payload": '{"note": "fixed after invalid JSON"}',
                },
            )
            assert status == 200, (status, body[:300])
            is_error, result = extract_result(body)
            assert not is_error, result
            after = table_count(db_path, "authorities")
            assert after == before + 1

        finally:
            console_proc.terminate()
            try:
                console_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console_proc.kill()

    print("console_0_6_malformed_json_payload: OK")
    print("  invalid JSON in payload field: 400 with actionable message, not 500; nothing reached the Kernel")
    print("  corrected payload on resubmit: succeeds normally")


if __name__ == "__main__":
    main()
