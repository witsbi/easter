"""EASTER-DOGFOOD-0, step 5: grant revocation while MCP remains
available, and re-granting -- against the LIVE project Kernel db,
using Clawde's real DOGFOOD-0 grant, not a synthetic authority test.

    1. Nathan/root revokes Clawde's grant through the Console.
    2. Clawde's independent MCP session (still connected -- MCP
       transport access is untouched by the revoke) attempts another
       Transition and is rejected by the Kernel. This is a genuine
       REJECTED receipt in the real project history, not staged.
    3. Nathan/root issues a new Grant to Clawde through the Console.
    4. Clawde transitions again, successfully, closing out the
       DOGFOOD-0 State for this experiment.

This is the same MCP-access-vs-Kernel-Authority property EASTER-MCP-0
and EASTER-CONSOLE-0 already demonstrated in isolated /tmp dbs --
exercised here for real, on Clawde's actual live grant, as the brief's
"where practical" list asks.
"""

from __future__ import annotations

import asyncio
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

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
AUTHORITY_ID = "authority:dogfood-0-clawde"

DOGFOOD_0_LATEST_STATE_ID = "state:7a415aee-2ad6-44c0-983b-86296e333b22"
CLAWDE_GRANT_ID = "grant:9e9de008-2301-4e39-a30f-2bbde8338bc9"

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


async def clawde_attempt_transition(grant_id: str, status: str) -> tuple[bool, object]:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        cwd=str(HERE),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            state_result = await session.call_tool("get_state", {"state_id": DOGFOOD_0_LATEST_STATE_ID})
            current_state = json.loads(state_result.content[0].text)
            updated_payload = dict(current_state["payload"])
            updated_payload["status"] = status

            result = await session.call_tool(
                "transition",
                {
                    "requester_identity_id": CLAWDE,
                    "from_state_id": DOGFOOD_0_LATEST_STATE_ID,
                    "authority_grant_id": grant_id,
                    "new_state_payload": updated_payload,
                },
            )
            if result.is_error:
                return True, result.content[0].text
            return False, json.loads(result.content[0].text)


def main() -> None:
    port = free_port()
    env = dict(os.environ)
    env.pop("KERNEL_DB_PATH", None)
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

        # 1. Nathan/root revokes Clawde's grant through the Console
        # (typed confirmation, the real HTML form).
        body = http_post_form(
            port,
            "/grant/revoke",
            {
                "requester_identity_id": NATHAN,
                "authority_grant_id": ROOT,
                "grant_id": CLAWDE_GRANT_ID,
                "confirm_grant_id": CLAWDE_GRANT_ID,
                "reason": "EASTER-DOGFOOD-0: exercising revoke-while-MCP-available",
            },
        )
        is_error, revoke_result = extract_result(body)
        assert not is_error, revoke_result

        # 2. Clawde's independent MCP session attempts another
        # Transition and is rejected -- a genuine REJECTED receipt.
        is_error, rejected_result = asyncio.run(
            clawde_attempt_transition(CLAWDE_GRANT_ID, "revoked_grant_rejected_as_expected")
        )
        assert is_error, "revoked grant must be rejected by the Kernel"
        assert "revoked" in rejected_result and CLAWDE_GRANT_ID in rejected_result, rejected_result

        # 3. Nathan/root issues a new Grant through the Console.
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
        is_error, new_grant_result = extract_result(body)
        assert not is_error, new_grant_result
        new_grant_id = new_grant_result["grant_id"]
        assert new_grant_id != CLAWDE_GRANT_ID

        # 4. Clawde transitions again, successfully.
        is_error, final_result = asyncio.run(
            clawde_attempt_transition(new_grant_id, "dogfood_0_experiment_complete")
        )
        assert not is_error, final_result

        print("dogfood_0_5_revoke_and_regrant: OK")
        print(f"  revoke_receipt_id={revoke_result['receipt_id']}")
        print(f"  rejected_transition_error={rejected_result}")
        print(f"  new_grant_id={new_grant_id}")
        print(f"  final_state_id={final_result['state_id']}")
        print(f"  final_transition_id={final_result['transition_id']}")
        print(f"  final_receipt_id={final_result['receipt_id']}")

    finally:
        console_proc.terminate()
        try:
            console_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            console_proc.kill()


if __name__ == "__main__":
    main()
