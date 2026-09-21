"""EASTER-DOGFOOD-0, step 2: Nathan/root, using EASTER-CONSOLE-0 itself
(real HTTP server, real HTML forms), defines a DOGFOOD-0-scoped
Authority and issues a real Grant to identity:clawde -- against the
LIVE project Kernel db, not a throwaway copy.

This is the "root-issued Grant through the supported EASTER boundary"
step from the brief, and it deliberately dogfoods the Console that
Phase 1 just built rather than going straight to MCP for a step the
Console does support.
"""

from __future__ import annotations

import html
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
AUTHORITY_ID = "authority:dogfood-0-clawde"

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


def http_post_form(port: int, path: str, fields: dict[str, str]) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = urllib.parse.urlencode(fields)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return text


def extract_result(page_text: str) -> tuple[bool, object]:
    match = PRE_BLOCK_RE.search(page_text)
    assert match is not None, f"no <pre> result block found: {page_text[:300]!r}"
    raw = html.unescape(match.group(1))
    is_error = "MCP tool error" in page_text
    try:
        return is_error, json.loads(raw)
    except json.JSONDecodeError:
        return is_error, raw


def main() -> None:
    port = free_port()
    env = dict(os.environ)
    env.pop("KERNEL_DB_PATH", None)  # deliberately: use the live project db, mcp_server.py's own default
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

        body = http_post_form(
            port,
            "/authority/define",
            {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "authority_id": AUTHORITY_ID,
                "payload": json.dumps({"scope": "EASTER-DOGFOOD-0", "granted_to": CLAWDE}),
            },
        )
        is_error, define_result = extract_result(body)
        assert not is_error, define_result

        body = http_post_form(
            port,
            "/grant/issue",
            {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "identity_id": CLAWDE,
                "authority_id": AUTHORITY_ID,
            },
        )
        is_error, grant_result = extract_result(body)
        assert not is_error, grant_result
        grant_id = grant_result["grant_id"]

        print("dogfood_0_2_grant_clawde: OK")
        print(f"  authority_id={AUTHORITY_ID}")
        print(f"  grant_id={grant_id} (issued to {CLAWDE} via Console HTML forms)")
        print(f"  define_receipt_id={define_result['receipt_id']}")
        print(f"  grant_receipt_id={grant_result['receipt_id']}")

    finally:
        console_proc.terminate()
        try:
            console_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            console_proc.kill()


if __name__ == "__main__":
    main()
