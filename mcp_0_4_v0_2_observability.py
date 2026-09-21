"""EASTER-MCP-0 boundary tests for the v0.2 observability read surface
(V0_2_OBSERVABILITY_DESIGN.md section 0 / V0_2_OBSERVABILITY_RECEIPT.md).

Proves caller -> MCP -> Kernel for real: a genuine MCP stdio
subprocess, genuine JSON-RPC tool calls, results cross-checked against
a second, independent Kernel instance opened directly on the same db
file -- same rigor as mcp_0_1_vertical_slice.py.

Runs against a throwaway /tmp copy of data/kernel.db.
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

HERE = Path(__file__).parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def tool_result(result):
    """Decode an MCP tool result while preserving Kernel ``None``.

    The MCP SDK represents a successful tool returning Python ``None`` as
    ``CallToolResult(content=[])`` rather than a text block containing JSON
    ``null``. This is the established boundary convention used by
    Console-0's MCP client too; the adapter must keep returning the Kernel's
    ``None`` rather than inventing a not-found object or error.
    """
    if result.is_error:
        raise AssertionError(f"tool call returned an error: {result.content}")
    if not result.content:
        return None
    return json.loads(result.content[0].text)


async def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="mcp-0-v0-2-observability-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        params = StdioServerParameters(
            command=sys.executable,
            args=[str(HERE / "mcp_server.py")],
            env={"KERNEL_DB_PATH": str(db_path)},
            cwd=str(HERE),
        )

        direct = Kernel(db_path)

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Seed a small scenario through MCP itself: a new
                # identity, an authority, a grant, and a transition --
                # then read all of it back through the new v0.2 tools,
                # cross-checked against a direct, independent Kernel
                # instance on the same db file.
                setup = tool_result(
                    await session.call_tool(
                        "transition",
                        {
                            "requester_identity_id": NATHAN,
                            "from_state_id": GENESIS,
                            "authority_grant_id": ROOT,
                            "new_state_payload": {"probe": "mcp-0-v0-2-observability"},
                            "new_identities": [
                                {"identity_id": "identity:mcp-0-v0-2-obs-test", "payload": {}}
                            ],
                        },
                    )
                )
                state_id = setup["state_id"]

                authority_id = "authority:mcp-0-v0-2-obs-test"
                tool_result(
                    await session.call_tool(
                        "define_authority",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "authority_id": authority_id,
                        },
                    )
                )
                grant_result = tool_result(
                    await session.call_tool(
                        "grant",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "identity_id": "identity:mcp-0-v0-2-obs-test",
                            "authority_id": authority_id,
                        },
                    )
                )
                grant_id = grant_result["grant_id"]

                evidence_result = tool_result(
                    await session.call_tool(
                        "record_evidence",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "payload": {"probe": "mcp-0-v0-2-observability-evidence"},
                        },
                    )
                )
                evidence_id = evidence_result["evidence_id"]

                child_transition = tool_result(
                    await session.call_tool(
                        "transition",
                        {
                            "requester_identity_id": "identity:mcp-0-v0-2-obs-test",
                            "from_state_id": state_id,
                            "authority_grant_id": grant_id,
                            "new_state_payload": {"probe": "mcp-0-v0-2-observability-child"},
                        },
                    )
                )

                # A genuine FAILED operation, for get_exception_by_receipt.
                failed = await session.call_tool(
                    "transition",
                    {
                        "requester_identity_id": NATHAN,
                        "from_state_id": state_id,
                        "authority_grant_id": ROOT,
                        "new_state_payload": {"probe": "mcp-0-v0-2-observability-failed"},
                        "evidence_ids": ["evidence:does-not-exist-mcp-0-v0-2-obs"],
                    },
                )
                assert failed.is_error
                failed_receipt_id = failed.content[0].text.split("receipt=")[1].rstrip("]")

                # ---- get_identity ----
                identity = tool_result(
                    await session.call_tool("get_identity", {"identity_id": "identity:mcp-0-v0-2-obs-test"})
                )
                assert identity["identity_id"] == "identity:mcp-0-v0-2-obs-test"
                assert tool_result(
                    await session.call_tool("get_identity", {"identity_id": "identity:does-not-exist"})
                ) is None

                # ---- get_authority ----
                authority = tool_result(await session.call_tool("get_authority", {"authority_id": authority_id}))
                assert authority["authority_id"] == authority_id
                assert authority["is_root"] is False
                assert tool_result(
                    await session.call_tool("get_authority", {"authority_id": "authority:does-not-exist"})
                ) is None

                # ---- get_evidence ----
                evidence = tool_result(await session.call_tool("get_evidence", {"evidence_id": evidence_id}))
                assert evidence["payload"]["probe"] == "mcp-0-v0-2-observability-evidence"
                assert tool_result(
                    await session.call_tool("get_evidence", {"evidence_id": "evidence:does-not-exist"})
                ) is None

                # ---- get_transition ----
                transition = tool_result(
                    await session.call_tool(
                        "get_transition", {"transition_id": child_transition["transition_id"]}
                    )
                )
                assert transition["from_state_id"] == state_id
                assert transition["authority_grant_id"] == grant_id
                assert tool_result(
                    await session.call_tool("get_transition", {"transition_id": "transition:does-not-exist"})
                ) is None

                # ---- get_exception_by_receipt ----
                exception = tool_result(
                    await session.call_tool("get_exception_by_receipt", {"receipt_id": failed_receipt_id})
                )
                assert exception["payload"]["reason"] == "sqlite integrity failure"
                assert tool_result(
                    await session.call_tool(
                        "get_exception_by_receipt", {"receipt_id": child_transition["receipt_id"]}
                    )
                ) is None, "an ACCEPTED receipt must never have a fabricated Exception"
                assert tool_result(
                    await session.call_tool(
                        "get_exception_by_receipt", {"receipt_id": "receipt:does-not-exist"}
                    )
                ) is None

                # ---- list_grants_for_identity ----
                grants_page = tool_result(
                    await session.call_tool(
                        "list_grants_for_identity", {"identity_id": "identity:mcp-0-v0-2-obs-test"}
                    )
                )
                assert {g["grant_id"] for g in grants_page["items"]} == {grant_id}

                # ---- list_transitions_from_state ----
                from_state_page = tool_result(
                    await session.call_tool("list_transitions_from_state", {"state_id": state_id})
                )
                from_state_ids = {t["transition_id"] for t in from_state_page["items"]}
                assert child_transition["transition_id"] in from_state_ids

                # ---- list_transitions_by_grant ----
                by_grant_page = tool_result(
                    await session.call_tool("list_transitions_by_grant", {"authority_grant_id": grant_id})
                )
                assert {t["transition_id"] for t in by_grant_page["items"]} == {
                    child_transition["transition_id"]
                }

                # ---- list_records: opaque cursor pagination over real MCP transport ----
                page_1 = tool_result(await session.call_tool("list_records", {"record_type": "identity", "limit": 1}))
                assert len(page_1["items"]) == 1
                assert page_1["next_after"] is not None
                page_2 = tool_result(
                    await session.call_tool(
                        "list_records",
                        {"record_type": "identity", "after": page_1["next_after"], "limit": 1},
                    )
                )
                assert len(page_2["items"]) == 1
                assert page_1["items"][0]["identity_id"] != page_2["items"][0]["identity_id"]

                # ---- invalid record_type surfaces as a real tool error, not a crash ----
                bad_type = await session.call_tool("list_records", {"record_type": "not-a-real-type"})
                assert bad_type.is_error
                assert "unknown record_type" in bad_type.content[0].text

        # Cross-check against a second, independent Kernel instance,
        # opened directly on the same db file, never through MCP.
        assert direct.get_identity("identity:mcp-0-v0-2-obs-test") is not None
        assert direct.get_authority(authority_id) is not None
        assert direct.get_transition(child_transition["transition_id"]) is not None
        direct_exception = direct.get_exception_by_receipt(failed_receipt_id)
        assert direct_exception is not None
        assert direct_exception["payload"]["reason"] == "sqlite integrity failure"

    print("mcp_0_4_v0_2_observability: OK")
    print("  all 9 accepted v0.2 tools reached the real Kernel over real MCP stdio transport")
    print(f"  grant_id={grant_id}")
    print(f"  failed_receipt_id={failed_receipt_id} -> Exception retrieved through MCP")


if __name__ == "__main__":
    asyncio.run(main())
