"""EASTER-DOGFOOD-0, step 1: bootstrap.

This script's first real run (against the LIVE project Kernel db,
data/kernel.db -- not a throwaway /tmp copy, per the brief's "actual
OpenClaw/Clawde operation" requirement) attempted to create a new
identity:clawde via transition()'s new_identities parameter. That call
genuinely failed:

    receipt:b015c2db-5529-42eb-b43c-9c71725daad3, outcome=FAILED,
    reason="sqlite integrity failure"

FRICTION OBSERVED, organically (not manufactured -- this is a real
mistake this dogfood run made and then had to diagnose):

  Actor: Clawde.
  Task: create a persistent identity for itself as part of onboarding
    onto EASTER.
  Exact question that could not be answered through the supported
    boundary: "why did this operation fail?" get_receipt (the only
    supported inspection point for a FAILED outcome) returns only the
    generic reason "sqlite integrity failure" -- it does not say
    which constraint, on which table, or with which value.
  Why existing supported operations were insufficient: EASTER-MCP-0
    has no get_exception, and the actual diagnostic detail
    ("UNIQUE constraint failed: identities.identity_id") lives only in
    exceptions.payload.details.
  Workaround: direct, unsupported SQLite inspection of the live db
    (explicitly outside the boundary this whole experiment is meant to
    respect) was the only way to learn the real cause -- identity:clawde
    already existed, created 2026-09-19T21:22:07Z with payload
    {"name": "Clawde", "role": "persistent_identity"}, already holding
    prior grants under authority:clawde-scope-alpha from earlier kernel
    work in this project, predating this session's memory. Diagnosis
    required exactly the private-internals access this experiment
    otherwise avoids -- a second, sharper illustration of the same
    Exception-retrieval gap MCP-0 already recorded, now with a concrete
    real failure behind it instead of a hypothetical.
  Blocking or inconvenient: blocking for root-cause diagnosis through
    the supported boundary alone (the generic reason does not tell you
    what to do differently); merely inconvenient for actually
    proceeding (the fix was simple once found: identity:clawde was
    already exactly what DOGFOOD-0 needed).

This also organically satisfies the brief's "where practical, exercise
... failed operations" item -- unplanned, not manufactured.

Corrected step: reuse the existing identity:clawde (it already has
exactly the "persistent, addressable identity" shape DOGFOOD-0 wants)
and commit the initial DOGFOOD-0 project State as a plain transition,
no new_identities needed.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"
CLAWDE = "identity:clawde"

FAILED_ATTEMPT_RECEIPT_ID = "receipt:b015c2db-5529-42eb-b43c-9c71725daad3"

DOGFOOD_0_INITIAL_PAYLOAD = {
    "project": "EASTER-DOGFOOD-0",
    "objective": (
        "Exercise EASTER (Kernel v0.1 + EASTER-MCP-0 + EASTER-CONSOLE-0) as part "
        "of real OpenClaw/Clawde operation, not a synthetic kernel test, and "
        "produce a classified friction log."
    ),
    "status": "in_progress",
    "completed_work": [
        "EASTER-MCP-0 merged to main (PR #12, commit db46679)",
        "EASTER-CONSOLE-0 implemented and verified this session (see CONSOLE_0_RECEIPT.md)",
        (
            "Discovered identity:clawde already exists from earlier kernel work "
            "(created 2026-09-19T21:22:07Z) after a real FAILED transition attempt "
            f"({FAILED_ATTEMPT_RECEIPT_ID}) tried to recreate it"
        ),
    ],
    "next_action": (
        "Clawde (identity:clawde) retrieves this State through MCP, does real "
        "DOGFOOD-0 work, records Evidence, submits a Transition, and preserves "
        "the Receipt; Nathan/root then exercises grant revoke/re-grant against "
        "Clawde's live grant while MCP remains available."
    ),
}


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        cwd=str(HERE),
        # No KERNEL_DB_PATH override: this deliberately targets the
        # live project Kernel db (mcp_server.py's own default), not a
        # throwaway copy -- this is the real DOGFOOD-0 operation.
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Confirm, through MCP itself, that get_receipt's view of
            # the earlier real failure is exactly as limited as
            # described above (no diagnostic detail beyond the
            # generic reason).
            failed_receipt = await session.call_tool(
                "get_receipt", {"receipt_id": FAILED_ATTEMPT_RECEIPT_ID}
            )
            failed_receipt_json = json.loads(failed_receipt.content[0].text)
            assert failed_receipt_json["outcome"] == "FAILED"
            assert failed_receipt_json["payload"] == {"reason": "sqlite integrity failure"}

            # Confirm identity:clawde is reachable the supported way
            # too, for this record -- via a grant already known to be
            # held by it (grant:clawde-alpha, discovered only through
            # the unsupported direct-SQL fallback described above).
            existing_grant = await session.call_tool("get_grant", {"grant_id": "grant:clawde-alpha"})
            existing_grant_json = json.loads(existing_grant.content[0].text)
            assert existing_grant_json["identity_id"] == CLAWDE

            result = await session.call_tool(
                "transition",
                {
                    "requester_identity_id": NATHAN,
                    "from_state_id": GENESIS,
                    "authority_grant_id": ROOT,
                    "new_state_payload": DOGFOOD_0_INITIAL_PAYLOAD,
                },
            )
            assert not result.is_error, result.content
            committed = json.loads(result.content[0].text)
            print("dogfood_0_1_bootstrap: OK")
            print(f"  reused_existing_identity={CLAWDE}")
            print(f"  failed_attempt_receipt_id={FAILED_ATTEMPT_RECEIPT_ID} (genuine, unplanned FAILED outcome)")
            print(f"  dogfood_0_state_id={committed['state_id']}")
            print(f"  transition_id={committed['transition_id']}")
            print(f"  receipt_id={committed['receipt_id']}")


if __name__ == "__main__":
    asyncio.run(main())
