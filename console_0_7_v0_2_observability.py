"""Console regression for the supported EASTER-MCP v0.2 read surface.

This drives the real Console HTTP server and its real MCP subprocess. It
checks that all six kernel primitive surfaces now have truthful inspection
coverage, that Exception retrieval is reachable, and that branch/list reads
remain bounded and unranked.
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

HERE = Path(__file__).parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"
PRE = re.compile(r"<pre>(.*?)</pre>", re.DOTALL)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_console(port: int) -> None:
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/")
            response = conn.getresponse()
            response.read()
            conn.close()
            if response.status == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError("console did not become ready")


def http_get(port: int, path: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read().decode()
    conn.close()
    return response.status, body


def result(body: str) -> object:
    match = PRE.search(body)
    assert match is not None, body[:500]
    return json.loads(html.unescape(match.group(1)))


async def seed(db_path: Path) -> dict[str, str]:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        cwd=str(HERE),
        env={"KERNEL_DB_PATH": str(db_path)},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            evidence_call = await session.call_tool(
                "record_evidence",
                {
                    "requester_identity_id": NATHAN,
                    "authority_grant_id": ROOT,
                    "payload": {"probe": "console-v0-2"},
                },
            )
            evidence = json.loads(evidence_call.content[0].text)
            committed = []
            for branch in ("a", "b"):
                transition_call = await session.call_tool(
                    "transition",
                    {
                        "requester_identity_id": NATHAN,
                        "from_state_id": GENESIS,
                        "authority_grant_id": ROOT,
                        "new_state_payload": {"branch": branch},
                        "evidence_ids": [evidence["evidence_id"]],
                    },
                )
                committed.append(json.loads(transition_call.content[0].text))

            rejected = await session.call_tool(
                "transition",
                {
                    "requester_identity_id": NATHAN,
                    "from_state_id": "state:does-not-exist",
                    "authority_grant_id": ROOT,
                    "new_state_payload": {"probe": "rejected"},
                },
            )
            text = rejected.content[0].text
            receipt_id = re.search(r"\[receipt=([^\]]+)\]", text).group(1)
            return {
                "state_id": committed[0]["state_id"],
                "transition_id": committed[0]["transition_id"],
                "receipt_id": committed[0]["receipt_id"],
                "evidence_id": evidence["evidence_id"],
                "failure_receipt_id": receipt_id,
            }


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="console-0-v0-2-", suffix=".db") as tmp:
        tmp.close()
        db_path = Path(tmp.name)
        shutil.copy2(source, db_path)
        seeded = asyncio.run(seed(db_path))

        port = free_port()
        env = dict(os.environ)
        env.update({"KERNEL_DB_PATH": str(db_path), "CONSOLE_HOST": "127.0.0.1", "CONSOLE_PORT": str(port)})
        process = subprocess.Popen(
            [sys.executable, str(HERE / "console.py")],
            cwd=str(HERE),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_console(port)

            for path in (
                f"/identity?identity_id={NATHAN}",
                "/authority?authority_id=" + urllib.parse.quote("authority:root"),
                f"/evidence?evidence_id={seeded['evidence_id']}",
                f"/transition?transition_id={seeded['transition_id']}",
                f"/receipt?receipt_id={seeded['receipt_id']}",
                f"/exception?receipt_id={seeded['failure_receipt_id']}",
            ):
                status, body = http_get(port, path)
                assert status == 200, (path, status, body[:300])
                assert result(body) is not None, (path, body[:300])

            status, body = http_get(
                port,
                "/transitions/from-state?state_id=state%3Agenesis&limit=1",
            )
            assert status == 200
            first_page = result(body)
            assert len(first_page["items"]) == 1
            assert first_page["next_after"]
            assert "not authoritative commit order" in body
            assert "preferred" in body

            cursor = urllib.parse.quote(first_page["next_after"], safe="")
            status, body = http_get(
                port,
                f"/transitions/from-state?state_id=state%3Agenesis&after={cursor}&limit=1",
            )
            assert status == 200
            second_page = result(body)
            assert len(second_page["items"]) == 1
            assert second_page["items"][0]["transition_id"] != first_page["items"][0]["transition_id"]

            status, body = http_get(port, "/browse?record_type=transition&limit=1")
            assert status == 200
            assert len(result(body)["items"]) == 1
            assert "unfiltered flat record view" in body

            malformed_limit_paths = (
                f"/grants?identity_id={NATHAN}&limit=abc",
                "/transitions/from-state?state_id=state%3Agenesis&limit=abc",
                "/transitions/by-grant?authority_grant_id="
                + urllib.parse.quote(ROOT)
                + "&limit=abc",
                "/browse?record_type=transition&limit=abc",
            )
            for path in malformed_limit_paths:
                status, body = http_get(port, path)
                assert status == 400, (path, status, body[:300])
                assert "Invalid limit: enter an integer." in body
                assert "<form" in body
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    print("console_0_7_v0_2_observability: OK")
    print("  v0.2 getters, Exception retrieval, branch pagination, and record browsing verified")
    print("  malformed limits: 400 form validation across all four paginated routes, not 500")


if __name__ == "__main__":
    main()
