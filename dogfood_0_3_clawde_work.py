"""EASTER-DOGFOOD-0, step 3: Clawde does real DOGFOOD-0 work through MCP.

Clawde (identity:clawde), using the grant Nathan/root issued through
the Console in step 2, retrieves the current DOGFOOD-0 State, records
genuine Evidence (the actual friction discovery from step 1 -- not a
synthetic payload), submits a Transition updating that State to
reflect real progress, and preserves the resulting Receipt.

This is the actual DOGFOOD-0 task: producing this experiment's own
record. Nothing here is a stand-in for "real work" -- it is the real
work, per the brief's instruction not to manufacture unnecessary
complexity just to exercise the boundary.

Architecture note: Clawde talks to MCP directly here, not through the
Console -- matching the brief's own diagram (Clawde/OpenClaw -> MCP ->
Kernel, distinct from Nathan -> Console -> MCP -> Kernel). The Console
is Nathan's control surface, not Clawde's.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).parent
CLAWDE = "identity:clawde"

# Fixed, already-committed ids from steps 1 and 2 of this real dogfood
# run (see dogfood_0_1_bootstrap.py / dogfood_0_2_grant_clawde.py
# output) -- these are genuine recorded history on the live db, not
# placeholders.
DOGFOOD_0_STATE_ID = "state:eb392325-a968-42c2-9503-895a1f664b6a"
CLAWDE_GRANT_ID = "grant:9e9de008-2301-4e39-a30f-2bbde8338bc9"


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        cwd=str(HERE),
        # No KERNEL_DB_PATH override: live project db, same as steps 1-2.
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Retrieve the relevant State through MCP.
            state_result = await session.call_tool("get_state", {"state_id": DOGFOOD_0_STATE_ID})
            current_state = json.loads(state_result.content[0].text)
            assert current_state is not None
            assert current_state["payload"]["project"] == "EASTER-DOGFOOD-0"

            # 3. Record genuine Evidence: the real friction discovery
            # from step 1, admitted under Clawde's own grant.
            evidence_result = await session.call_tool(
                "record_evidence",
                {
                    "requester_identity_id": CLAWDE,
                    "authority_grant_id": CLAWDE_GRANT_ID,
                    "payload": {
                        "kind": "friction_observation",
                        "source": "dogfood_0_1_bootstrap.py",
                        "observation": (
                            "Attempting to create identity:clawde failed with a real "
                            "FAILED receipt (sqlite integrity failure / UNIQUE constraint "
                            "on identities.identity_id) because it already existed from "
                            "earlier kernel work. Diagnosing the exact cause required "
                            "direct SQLite inspection outside the supported EASTER-MCP-0 "
                            "boundary, since get_receipt exposes only the generic reason "
                            "string, not exceptions.payload's diagnostic detail."
                        ),
                        "failed_attempt_receipt_id": "receipt:b015c2db-5529-42eb-b43c-9c71725daad3",
                    },
                },
            )
            assert not evidence_result.is_error, evidence_result.content
            evidence = json.loads(evidence_result.content[0].text)

            # 4. Submit a Transition through MCP, citing that Evidence.
            updated_payload = dict(current_state["payload"])
            updated_payload["status"] = "console_and_grant_lifecycle_verified"
            updated_payload["completed_work"] = current_state["payload"]["completed_work"] + [
                (
                    "Clawde received a DOGFOOD-0-scoped Grant "
                    f"({CLAWDE_GRANT_ID}) issued by Nathan/root through EASTER-CONSOLE-0"
                ),
                "Clawde retrieved this State and recorded genuine friction Evidence through MCP",
            ]
            updated_payload["next_action"] = (
                "Nathan/root exercises grant revoke + re-grant against Clawde's live "
                "grant while MCP remains available, then session-restart recovery is "
                "demonstrated, then DOGFOOD_0_RECEIPT.md is written with classified findings."
            )

            transition_result = await session.call_tool(
                "transition",
                {
                    "requester_identity_id": CLAWDE,
                    "from_state_id": DOGFOOD_0_STATE_ID,
                    "authority_grant_id": CLAWDE_GRANT_ID,
                    "new_state_payload": updated_payload,
                    "evidence_ids": [evidence["evidence_id"]],
                },
            )
            assert not transition_result.is_error, transition_result.content
            committed = json.loads(transition_result.content[0].text)

            # 5. Obtain and preserve the resulting Receipt.
            receipt_result = await session.call_tool("get_receipt", {"receipt_id": committed["receipt_id"]})
            receipt = json.loads(receipt_result.content[0].text)
            assert receipt["outcome"] == "ACCEPTED"

            print("dogfood_0_3_clawde_work: OK")
            print(f"  evidence_id={evidence['evidence_id']}")
            print(f"  new_state_id={committed['state_id']}")
            print(f"  transition_id={committed['transition_id']}")
            print(f"  receipt_id={committed['receipt_id']}")


if __name__ == "__main__":
    asyncio.run(main())
