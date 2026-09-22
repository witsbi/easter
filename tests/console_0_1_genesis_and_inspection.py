"""EASTER-CONSOLE-0 verification 1-2: Console can retrieve Genesis and
inspect a known State/Receipt/Grant.

Launches console.py as a real subprocess (real uvicorn HTTP server on
127.0.0.1), which itself spawns mcp_server.py as a real subprocess over
stdio, against a throwaway /tmp copy of data/kernel.db (same
convention as the mcp_0_* tests). Drives the Console with real HTTP
requests -- no in-process shortcuts anywhere in this chain:

    this test --(HTTP)--> console.py --(MCP stdio)--> mcp_server.py --> Kernel

A known State/Receipt is seeded via a separate, direct MCP client
(mirroring how a real EASTER user would have produced them through
some other supported path) before the Console is asked to inspect it,
since Console-0 does not expose transition/record_evidence as
controls -- inspection only.
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


def http_get(port: int, path: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    return resp.status, text


def extract_result(page_text: str) -> tuple[bool, object]:
    """Pull the <pre> result block out of a rendered Console page."""
    match = PRE_BLOCK_RE.search(page_text)
    assert match is not None, f"no <pre> result block found in page: {page_text[:300]!r}"
    raw = html.unescape(match.group(1))
    try:
        return ("error" in page_text.lower() and "MCP tool error" in page_text), json.loads(raw)
    except json.JSONDecodeError:
        return True, raw


async def seed_known_records(db_path: Path) -> dict[str, str]:
    """Produce a real State/Transition/Receipt via a direct MCP client (not the Console)."""
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        env={"KERNEL_DB_PATH": str(db_path)},
        cwd=str(HERE),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            evidence_result = await session.call_tool(
                "record_evidence",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "payload": {"probe": "console-0-seed"},
                },
            )
            evidence = json.loads(evidence_result.content[0].text)

            transition_result = await session.call_tool(
                "transition",
                {
                    "requester_identity_id": NATHAN,
                    "from_state_id": GENESIS,
                    "authority_grant_id": ROOT,
                    "new_state_payload": {"probe": "console-0-seed"},
                    "evidence_ids": [evidence["evidence_id"]],
                },
            )
            committed = json.loads(transition_result.content[0].text)
            return committed


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="console-0-genesis-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        seeded = asyncio.run(seed_known_records(db_path))
        state_id = seeded["state_id"]
        receipt_id = seeded["receipt_id"]

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

            # 1. Console can retrieve Genesis.
            status, body = http_get(port, "/state/genesis")
            assert status == 200
            is_error, genesis = extract_result(body)
            assert not is_error
            assert genesis["state_id"] == GENESIS
            assert genesis["payload"]["genesis"] == 1

            # 2. Console can inspect a known State.
            status, body = http_get(port, f"/state?state_id={state_id}")
            assert status == 200
            is_error, state = extract_result(body)
            assert not is_error
            assert state["state_id"] == state_id
            assert state["payload"]["probe"] == "console-0-seed"

            # 2. Console can inspect a known Receipt.
            status, body = http_get(port, f"/receipt?receipt_id={receipt_id}")
            assert status == 200
            is_error, receipt = extract_result(body)
            assert not is_error
            assert receipt["receipt_id"] == receipt_id
            assert receipt["outcome"] == "ACCEPTED"

            # 2. Console can inspect a known Grant.
            status, body = http_get(port, f"/grant?grant_id={ROOT}")
            assert status == 200
            is_error, grant = extract_result(body)
            assert not is_error
            assert grant["grant_id"] == ROOT
            assert grant["identity_id"] == NATHAN

            # Unknown ids come back as an explicit null result, not a
            # crash or an invented "not found" application concept.
            status, body = http_get(port, "/state?state_id=state:does-not-exist")
            assert status == 200
            is_error, missing = extract_result(body)
            assert not is_error
            assert missing is None

        finally:
            console_proc.terminate()
            try:
                console_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                console_proc.kill()

    print("console_0_1_genesis_and_inspection: OK")
    print(f"  state_id={state_id}")
    print(f"  receipt_id={receipt_id}")


if __name__ == "__main__":
    main()
