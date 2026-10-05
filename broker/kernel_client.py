"""Shared MCP stdio client for userland services that cite kernel Evidence.

Identical in shape to ``console.py``'s ``ConsoleMCPClient`` -- spawns
``mcp_server.py`` as a genuinely separate process over stdio, the same
way any other MCP client (Clawde, the gateway) would. There is no
in-process shortcut to the Kernel anywhere in this module. Factored out
of ``console.py`` rather than duplicated, since the broker and the
setup-wizard backend (build order #2) both need the identical pattern.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVER_PATH = REPO_ROOT / "mcp_server.py"


class KernelMCPClient:
    """Owns one long-lived MCP session against the kernel's MCP boundary."""

    def __init__(self, kernel_db_path: str | None = None) -> None:
        self._kernel_db_path = kernel_db_path
        self._stack: contextlib.AsyncExitStack | None = None
        self.session: ClientSession | None = None

    async def start(self) -> None:
        # Resolve to an absolute path: the child is spawned with
        # cwd=REPO_ROOT, so a relative KERNEL_DB_PATH from this
        # process's own cwd would otherwise resolve against the wrong
        # directory -- the same footgun console.py's client already
        # guards against.
        db_path = (
            os.path.abspath(self._kernel_db_path)
            if self._kernel_db_path
            else None
        )
        env = {"KERNEL_DB_PATH": db_path} if db_path else None
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SERVER_PATH)],
            cwd=str(REPO_ROOT),
            env=env,
        )
        self._stack = contextlib.AsyncExitStack()
        read, write = await self._stack.enter_async_context(
            stdio_client(params)
        )
        self.session = await self._stack.enter_async_context(
            ClientSession(read, write)
        )
        await self.session.initialize()

    async def stop(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def call(self, name: str, arguments: dict[str, Any]) -> tuple[bool, Any]:
        """Call an MCP tool. Returns (is_error, parsed_json_or_text)."""
        assert self.session is not None, "KernelMCPClient not started"
        result = await self.session.call_tool(name, arguments)
        text = result.content[0].text if result.content else "null"
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = text
        return result.is_error, parsed
