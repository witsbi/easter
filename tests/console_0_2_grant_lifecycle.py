"""EASTER-CONSOLE-0 verification 3-6: issue a real Grant through the
Console, revoke it through the Console, and show that an MCP client
holding that grant is affected exactly the way EASTER-MCP-0's own
authority boundary test demonstrated -- Console is just another
caller of the same MCP boundary, it does not change Kernel Authority
semantics.

    3. Console can issue a real Grant.
    4. Console can revoke that Grant.
    5. An MCP client possessing the revoked grant remains connected
       but cannot perform an authorized transition.
    6. A newly issued valid Grant restores the ability to transition.

All Console actions here go through the real HTML forms (POST,
url-encoded, exactly what a browser would send) -- not a JSON
shortcut -- so this is genuine Nathan/Console -> MCP -> Kernel
runtime evidence, not an in-process call.
"""

from __future__ import annotations

import asyncio
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

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"

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
    conn.request(
        "POST",
        path,
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return resp.status, text


def extract_result(page_text: str) -> tuple[bool, object]:
    match = PRE_BLOCK_RE.search(page_text)
    assert match is not None, f"no <pre> result block found in page: {page_text[:300]!r}"
    raw = html.unescape(match.group(1))
    is_error = "MCP tool error" in page_text
    try:
        return is_error, json.loads(raw)
    except json.JSONDecodeError:
        return is_error, raw


async def attempt_transition(db_path: Path, authority_grant_id: str, probe: str) -> tuple[bool, object]:
    """A separate MCP client -- not the Console -- exercising a grant.

    Represents "an MCP client possessing the grant" from the brief:
    a caller entirely independent of the Console, connected over its
    own stdio transport, using only the grant_id the Console issued.
    """
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        env={"KERNEL_DB_PATH": str(db_path)},
        cwd=str(HERE),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "transition",
                {
                    "requester_identity_id": NATHAN,
                    "from_state_id": GENESIS,
                    "authority_grant_id": authority_grant_id,
                    "new_state_payload": {"probe": probe},
                },
            )
            if result.is_error:
                return True, result.content[0].text
            return False, json.loads(result.content[0].text)


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="console-0-grant-lifecycle-", suffix=".db") as f:
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

            authority_id = "authority:console-0-grant-lifecycle-op"

            # Root defines a non-root Authority through the Console.
            status, body = http_post_form(
                port,
                "/authority/define",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "authority_id": authority_id,
                    "payload": "{}",
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result

            # 3. Console can issue a real Grant.
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
            first_grant_id = result["grant_id"]

            # A separate MCP client can transition using that grant.
            is_error, result = asyncio.run(
                attempt_transition(db_path, first_grant_id, "console-0-grant-lifecycle-first")
            )
            assert not is_error, result

            # 4. Console can revoke that Grant (typed confirmation, real form).
            status, body = http_post_form(
                port,
                "/grant/revoke",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "grant_id": first_grant_id,
                    "confirm_grant_id": first_grant_id,
                    "reason": "console-0-grant-lifecycle probe",
                },
            )
            assert status == 200
            is_error, result = extract_result(body)
            assert not is_error, result

            # 5. An MCP client possessing the revoked grant remains
            # connected (the call below completes and returns a
            # result -- it is not a dropped/refused connection) but
            # cannot perform an authorized transition.
            is_error, result = asyncio.run(
                attempt_transition(db_path, first_grant_id, "console-0-grant-lifecycle-revoked")
            )
            assert is_error, "revoked grant must be rejected by the Kernel"
            assert "revoked" in result and first_grant_id in result, result

            # Root issues a new Grant through the Console.
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
            second_grant_id = result["grant_id"]
            assert second_grant_id != first_grant_id

            # 6. A newly issued valid Grant restores the ability to transition.
            is_error, result = asyncio.run(
                attempt_transition(db_path, second_grant_id, "console-0-grant-lifecycle-second")
            )
            assert not is_error, result

        finally:
            console_proc.terminate()
            try:
                console_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console_proc.kill()

    print("console_0_2_grant_lifecycle: OK")
    print(f"  authority_id={authority_id}")
    print(f"  first_grant_id={first_grant_id} (issued, exercised, revoked, then rejected)")
    print(f"  second_grant_id={second_grant_id} (issued again, exercised successfully)")


if __name__ == "__main__":
    main()
