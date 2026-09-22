"""Regression tests for the supported fresh-install initializer."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from initialize import initialize_database
from kernel import Kernel


HERE = Path(__file__).resolve().parent.parent


async def verify_mcp(db_path: Path, identity_id: str) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        cwd=str(HERE),
        env={**os.environ, "KERNEL_DB_PATH": str(db_path)},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            genesis = await session.call_tool("get_genesis_state", {})
            assert json.loads(genesis.content[0].text)["state_id"] == "state:genesis"
            grant = await session.call_tool("get_grant", {"grant_id": "grant:genesis-root"})
            assert json.loads(grant.content[0].text)["identity_id"] == identity_id


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="easter-initialize-") as directory:
        db_path = Path(directory) / "data" / "kernel.db"
        identity_id = "identity:installer-choice'); DROP TABLE identities; --"
        initialize_database(db_path, identity_id)

        kernel = Kernel(db_path)
        assert kernel.get_grant("grant:genesis-root")["identity_id"] == identity_id
        assert kernel.get_receipt("receipt:genesis")["outcome"] == "BOOTSTRAP"
        assert kernel.get_genesis_state()["payload"] == {"genesis": 1, "version": "0.1"}

        try:
            initialize_database(db_path, "identity:someone-else")
        except FileExistsError:
            pass
        else:
            raise AssertionError("initializer must not overwrite an existing database")

        failed_path = Path(directory) / "failed" / "kernel.db"
        try:
            initialize_database(failed_path, "identity:bad-payload", root_identity_payload={"nan": float("nan")})
        except ValueError:
            pass
        else:
            raise AssertionError("invalid initialization must fail")
        assert not failed_path.exists()

        asyncio.run(verify_mcp(db_path, identity_id))
    print("initialize_test: OK")


if __name__ == "__main__":
    main()
