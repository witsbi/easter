"""EASTER-MCP-0 vertical slice: get_state -> record_evidence -> transition -> get_receipt.

Runs mcp_server.py as a real subprocess speaking MCP over stdio (not an
in-process function call) against a throwaway copy of the current
development database, matching this repo's existing regression-test
convention (see receipt_2_minimality.py). This produces genuine
runtime evidence that an MCP call reached the real Kernel: a second,
independent Kernel instance opened directly against the same on-disk
db (never through MCP) is used to cross-check that every record the
MCP tool calls claim to have produced is actually there.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from kernel import Kernel

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def tool_result(result) -> dict:
    """Unwrap a CallToolResult's own text content.

    Deliberately reads result.content (the tool's actual JSON return
    value) rather than result.structured_content: for a `dict | None`
    return annotation the MCP SDK wraps structured_content under an
    extra {"result": ...} envelope (anyOf output schemas aren't plain
    object schemas), which content[0].text never does.
    """
    if result.is_error:
        raise AssertionError(f"tool call returned an error: {result.content}")
    return json.loads(result.content[0].text)


async def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="mcp-0-vertical-slice-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        params = StdioServerParameters(
            command=sys.executable,
            args=[str(HERE / "mcp_server.py")],
            env={"KERNEL_DB_PATH": str(db_path)},
            cwd=str(HERE),
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. get_state: retrieve genesis through MCP.
                genesis = tool_result(
                    await session.call_tool("get_state", {"state_id": GENESIS})
                )
                assert genesis["state_id"] == GENESIS
                assert genesis["payload"]["genesis"] == 1

                # 2. record_evidence: admit new Evidence through MCP.
                evidence = tool_result(
                    await session.call_tool(
                        "record_evidence",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "payload": {"probe": "mcp-0-vertical-slice"},
                        },
                    )
                )
                evidence_id = evidence["evidence_id"]
                assert evidence_id.startswith("evidence:")

                # 3. transition: commit a new State citing that Evidence, through MCP.
                committed = tool_result(
                    await session.call_tool(
                        "transition",
                        {
                            "requester_identity_id": NATHAN,
                            "from_state_id": GENESIS,
                            "authority_grant_id": ROOT,
                            "new_state_payload": {"probe": "mcp-0-vertical-slice"},
                            "evidence_ids": [evidence_id],
                        },
                    )
                )
                state_id = committed["state_id"]
                transition_id = committed["transition_id"]
                receipt_id = committed["receipt_id"]

                # 4. get_receipt: retrieve the resulting Receipt through MCP.
                receipt = tool_result(
                    await session.call_tool("get_receipt", {"receipt_id": receipt_id})
                )
                assert receipt["outcome"] == "ACCEPTED"
                assert receipt["transition_id"] == transition_id

        # Cross-check: a second, independent Kernel instance opened
        # directly against the same db file (never through MCP)
        # confirms these are real, committed, authoritative kernel
        # records -- not an artifact of the MCP round-trip.
        direct = Kernel(db_path)
        direct_state = direct.get_state(state_id)
        assert direct_state is not None
        assert direct_state["payload"]["probe"] == "mcp-0-vertical-slice"

        direct_receipt = direct.get_receipt(receipt_id)
        assert direct_receipt is not None
        assert direct_receipt["outcome"] == "ACCEPTED"

        with direct.connect() as conn:
            evidence_row = conn.execute(
                "SELECT evidence_id FROM evidence WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
            assert evidence_row is not None

            link_row = conn.execute(
                "SELECT 1 FROM receipt_evidence WHERE receipt_id = ? AND evidence_id = ?",
                (receipt_id, evidence_id),
            ).fetchone()
            assert link_row is not None

    print("mcp_0_1_vertical_slice: OK")
    print(f"  state_id={state_id}")
    print(f"  transition_id={transition_id}")
    print(f"  evidence_id={evidence_id}")
    print(f"  receipt_id={receipt_id}")


if __name__ == "__main__":
    asyncio.run(main())
