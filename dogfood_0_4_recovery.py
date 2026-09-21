"""EASTER-DOGFOOD-0, step 4: session restart / recovery.

A brand new process, with no memory of steps 1-3 beyond the one
state_id it was told (exactly how a future Clawde session would
recover: told an id out-of-band, e.g. by Nathan or by OpenClaw's own
memory, since EASTER has no canonical-state concept to recover
"the" project state on its own -- see the friction note below),
opens a fresh MCP ClientSession -- its own new subprocess, its own new
stdio transport, no shared state with steps 1-3 -- and retrieves the
current DOGFOOD-0 State through the supported boundary.

This demonstrates recovery through EASTER: the project's State outlives
the process/session that produced it, and a later, unrelated session
can pick it back up using only the supported MCP boundary.

FRICTION OBSERVED: recovering "the project" here only worked because
this script was given the exact state_id in advance (hardcoded below,
copied from step 3's printed output). EASTER-MCP-0 has no supported
way to ask "what is the current/most relevant DOGFOOD-0 state" --
by design, the Kernel has no canonical-state concept (see kernel.py's
transition() docstring: "which state_id to continue from ... is
entirely a userland decision"). So "recovery" in practice depends
entirely on some out-of-band pointer (a receipt doc, a memory file, a
message from Nathan) supplying the id. This is not obviously a Kernel
gap -- it may be exactly the intended separation of concerns -- but it
is a real, concretely-felt dependency worth recording.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).parent

# The only reason this "new session" can recover anything: it was
# told this id out-of-band (here, copied from dogfood_0_3's printed
# output -- in a real future session, this would come from a memory
# file or a message from Nathan).
DOGFOOD_0_LATEST_STATE_ID = "state:7a415aee-2ad6-44c0-983b-86296e333b22"


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        cwd=str(HERE),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            recovered = await session.call_tool("get_state", {"state_id": DOGFOOD_0_LATEST_STATE_ID})
            recovered_state = json.loads(recovered.content[0].text)
            assert recovered_state is not None
            assert recovered_state["payload"]["project"] == "EASTER-DOGFOOD-0"
            assert recovered_state["payload"]["status"] == "console_and_grant_lifecycle_verified"

            print("dogfood_0_4_recovery: OK")
            print(f"  recovered_state_id={recovered_state['state_id']}")
            print(f"  status={recovered_state['payload']['status']}")
            print(f"  completed_work_count={len(recovered_state['payload']['completed_work'])}")
            print(f"  next_action={recovered_state['payload']['next_action']}")


if __name__ == "__main__":
    asyncio.run(main())
