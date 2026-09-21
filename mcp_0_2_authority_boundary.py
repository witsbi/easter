"""EASTER-MCP-0 authority boundary: MCP transport access != Kernel Authority.

Demonstrates, over real MCP stdio transport against a throwaway copy
of the current development database (see mcp_0_1_vertical_slice.py
for why):

  1. Nathan/root issues a valid grant to a test agent identity.
  2. Agent successfully performs an authorized transition through MCP.
  3. Nathan/root revokes that grant.
  4. Agent retains MCP transport access.
  5. Agent attempts another transition -- the MCP call still
     transports (a normal CallToolResult comes back, the process does
     not reject/drop the connection) but the Kernel rejects the
     operation according to its own existing Authority semantics.
  6. Nathan/root issues a new valid grant.
  7. Agent can again perform an authorized transition.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def tool_result(result) -> dict:
    if result.is_error:
        raise AssertionError(f"tool call returned an error: {result.content}")
    return json.loads(result.content[0].text)


async def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="mcp-0-authority-boundary-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        params = StdioServerParameters(
            command=sys.executable,
            args=[str(HERE / "mcp_server.py")],
            env={"KERNEL_DB_PATH": str(db_path)},
            cwd=str(HERE),
        )

        run_id = uuid.uuid4().hex[:8]
        agent_identity_id = f"identity:mcp-0-test-agent-{run_id}"
        authority_id = f"authority:mcp-0-test-op-{run_id}"

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Create the test agent identity as a side effect of a
                # root-authorized transition (identity creation has no
                # other supported entry point -- see transition()'s
                # new_identities parameter).
                tool_result(
                    await session.call_tool(
                        "transition",
                        {
                            "requester_identity_id": NATHAN,
                            "from_state_id": GENESIS,
                            "authority_grant_id": ROOT,
                            "new_state_payload": {"probe": "mcp-0-authority-boundary-setup"},
                            "new_identities": [
                                {"identity_id": agent_identity_id, "payload": {"role": "mcp-0-test-agent"}}
                            ],
                        },
                    )
                )

                # Root defines a non-root Authority the test agent can hold.
                tool_result(
                    await session.call_tool(
                        "define_authority",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "authority_id": authority_id,
                            "is_root": False,
                        },
                    )
                )

                # 1. Root grants that Authority to the test agent.
                first_grant = tool_result(
                    await session.call_tool(
                        "grant",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "identity_id": agent_identity_id,
                            "authority_id": authority_id,
                        },
                    )
                )
                first_grant_id = first_grant["grant_id"]

                # 2. Agent successfully performs an authorized transition through MCP.
                first_transition = tool_result(
                    await session.call_tool(
                        "transition",
                        {
                            "requester_identity_id": agent_identity_id,
                            "from_state_id": GENESIS,
                            "authority_grant_id": first_grant_id,
                            "new_state_payload": {"probe": "mcp-0-authority-boundary-first"},
                        },
                    )
                )
                first_receipt = tool_result(
                    await session.call_tool(
                        "get_receipt", {"receipt_id": first_transition["receipt_id"]}
                    )
                )
                assert first_receipt["outcome"] == "ACCEPTED"

                # 3. Root revokes that grant.
                tool_result(
                    await session.call_tool(
                        "revoke",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "grant_id": first_grant_id,
                            "reason": "mcp-0-authority-boundary probe",
                        },
                    )
                )

                # 4/5. Agent retains MCP transport access: the call still
                # transports and returns a normal CallToolResult (no
                # connection failure, no transport-level exception) --
                # but the Kernel rejects it under its own existing
                # Authority semantics.
                rejected = await session.call_tool(
                    "transition",
                    {
                        "requester_identity_id": agent_identity_id,
                        "from_state_id": GENESIS,
                        "authority_grant_id": first_grant_id,
                        "new_state_payload": {"probe": "mcp-0-authority-boundary-revoked"},
                    },
                )
                assert rejected.is_error is True, (
                    "revoked grant must be rejected by the Kernel, not silently accepted"
                )
                error_text = rejected.content[0].text
                assert "revoked" in error_text and first_grant_id in error_text, (
                    f"expected a Kernel revocation error naming {first_grant_id!r}, got: {error_text!r}"
                )

                # 6. Root issues a new valid grant.
                second_grant = tool_result(
                    await session.call_tool(
                        "grant",
                        {
                            "requester_identity_id": NATHAN,
                            "authority_grant_id": ROOT,
                            "identity_id": agent_identity_id,
                            "authority_id": authority_id,
                        },
                    )
                )
                second_grant_id = second_grant["grant_id"]
                assert second_grant_id != first_grant_id

                # 7. Agent can again perform an authorized transition.
                second_transition = tool_result(
                    await session.call_tool(
                        "transition",
                        {
                            "requester_identity_id": agent_identity_id,
                            "from_state_id": GENESIS,
                            "authority_grant_id": second_grant_id,
                            "new_state_payload": {"probe": "mcp-0-authority-boundary-second"},
                        },
                    )
                )
                second_receipt = tool_result(
                    await session.call_tool(
                        "get_receipt", {"receipt_id": second_transition["receipt_id"]}
                    )
                )
                assert second_receipt["outcome"] == "ACCEPTED"

    print("mcp_0_2_authority_boundary: OK")
    print(f"  agent_identity_id={agent_identity_id}")
    print(f"  authority_id={authority_id}")
    print(f"  first_grant_id={first_grant_id} (authorized, then revoked, then rejected)")
    print(f"  second_grant_id={second_grant_id} (authorized again after re-grant)")


if __name__ == "__main__":
    asyncio.run(main())
