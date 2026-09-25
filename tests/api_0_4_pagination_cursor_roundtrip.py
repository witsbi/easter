"""EASTER-API-0 black-box evidence: pagination cursors are passed through
opaquely, HTTP -> API -> MCP stdio -> Kernel.

Runs the real API server (which starts the real MCP stdio subprocess) and,
separately, an independent direct MCP session against the same throwaway
copy of the reference database. The test seeds its own history through the
supported POST /v1/transitions operation, so it does not depend on how much
history the reference database holds (a freshly initialized database has a
single State and a single Receipt). For two record types whose cursors have
different origins (State: created_at/id walk; Receipt: kernel append
sequence) it walks every page through HTTP with `after` fed back exactly as
returned, and proves against the direct MCP walk that:

  - every page is identical, and every cursor the API returns is
    byte-identical to the cursor MCP returned (the API never builds, parses,
    rewrites, or drops one);
  - the walk terminates on the same page (next_after null), with more than
    two pages, no duplicates and no gaps (record count == table row count);
  - an invalid cursor is rejected with the very message MCP produces for the
    same call, i.e. the API does not interpret cursors itself.
"""

from __future__ import annotations

import asyncio
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
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent.parent
PAGE_SIZE = 25
MAX_PAGES = 200
SEED_TRANSITIONS = 60
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_get(port: int, path: str) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def http_post(port: int, path: str, payload: dict[str, Any]) -> tuple[int, Any]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def seed_history(port: int) -> None:
    """Commit a chain of Transitions so States and Receipts each span >2 pages."""
    from_state_id = GENESIS
    for index in range(SEED_TRANSITIONS):
        status, body = http_post(
            port,
            "/v1/transitions",
            {
                "requester_identity_id": NATHAN,
                "from_state_id": from_state_id,
                "authority_grant_id": ROOT,
                "new_state_payload": {"probe": "api-0-cursor-seed", "index": index},
            },
        )
        assert status == 200, (index, status, body)
        from_state_id = body["state_id"]


def http_page(port: int, record_type: str, after: str | None) -> dict[str, Any]:
    query = f"limit={PAGE_SIZE}"
    if after is not None:
        query += "&after=" + urllib.parse.quote(after, safe="")
    status, body = http_get(port, f"/v1/records/{record_type}?{query}")
    assert status == 200, (status, body)
    return body


def walk_http(port: int, record_type: str) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    after: str | None = None
    while len(pages) < MAX_PAGES:
        page = http_page(port, record_type, after)
        pages.append(page)
        after = page["next_after"]
        if after is None:
            return pages
    raise AssertionError(f"{record_type}: did not terminate within {MAX_PAGES} pages")


async def walk_mcp(session: ClientSession, record_type: str) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    after: str | None = None
    while len(pages) < MAX_PAGES:
        result = await session.call_tool(
            "list_records", {"record_type": record_type, "after": after, "limit": PAGE_SIZE}
        )
        assert not result.is_error, result.content
        page = json.loads(result.content[0].text)
        pages.append(page)
        after = page["next_after"]
        if after is None:
            return pages
    raise AssertionError(f"{record_type}: did not terminate within {MAX_PAGES} pages")


async def direct_mcp_evidence(db_path: str, port: int) -> dict[str, Any]:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        env={"KERNEL_DB_PATH": db_path},
        cwd=str(HERE),
    )
    evidence: dict[str, Any] = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for record_type, id_key in (("state", "state_id"), ("receipt", "receipt_id")):
                mcp_pages = await walk_mcp(session, record_type)
                http_pages = await asyncio.to_thread(walk_http, port, record_type)

                assert len(http_pages) > 2, f"{record_type}: need >2 pages for a real round trip"
                assert http_pages == mcp_pages, f"{record_type}: HTTP pages differ from direct MCP pages"

                http_cursors = [page["next_after"] for page in http_pages]
                mcp_cursors = [page["next_after"] for page in mcp_pages]
                assert http_cursors == mcp_cursors, f"{record_type}: cursors were altered by the API"
                assert http_cursors[-1] is None and all(c is not None for c in http_cursors[:-1])

                ids = [item[id_key] for page in http_pages for item in page["items"]]
                assert len(ids) == len(set(ids)), f"{record_type}: duplicate records across pages"
                assert all(len(page["items"]) == PAGE_SIZE for page in http_pages[:-1])

                # No gap: the walk covers exactly the rows in the table.
                table = {"state": "states", "receipt": "receipts"}[record_type]
                with sqlite3.connect(db_path) as conn:
                    (row_count,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                assert len(ids) == row_count, f"{record_type}: walked {len(ids)} != {row_count} rows"
                evidence[record_type] = {
                    "pages": len(http_pages),
                    "records": len(ids),
                    "first_cursor": http_cursors[0],
                }

            # An invalid cursor is rejected by MCP/Kernel, not by the API: the
            # API's error text is MCP's own error text for the same call.
            bad_cursor = "not-a-cursor"
            direct = await session.call_tool(
                "list_records", {"record_type": "state", "after": bad_cursor, "limit": PAGE_SIZE}
            )
            status, body = await asyncio.to_thread(
                http_get, port, f"/v1/records/state?limit={PAGE_SIZE}&after={bad_cursor}"
            )
            assert direct.is_error and status == 400, (direct.is_error, status)
            assert body == {"error": direct.content[0].text}, (body, direct.content[0].text)
    return evidence


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="api-0-cursor-", suffix=".db") as f:
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
            deadline = time.time() + 15
            while True:
                try:
                    status, _ = http_get(port, "/healthz")
                    if status == 200:
                        break
                except OSError:
                    if time.time() > deadline:
                        raise
                    time.sleep(0.1)

            seed_history(port)
            evidence = asyncio.run(direct_mcp_evidence(str(db_path), port))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    print("api_0_4_pagination_cursor_roundtrip: OK")
    for record_type, item in evidence.items():
        print(
            f"  {record_type}: {item['pages']} pages / {item['records']} records, "
            f"HTTP walk == direct MCP walk, cursors byte-identical, no duplicates"
        )
        print(f"    first cursor: {item['first_cursor']}")
    print("  invalid cursor: API error text == MCP error text (API does not interpret cursors)")


if __name__ == "__main__":
    main()
