#!/usr/bin/env python3
"""
EASTER-CONSOLE-0 -- minimal human control surface over EASTER-MCP-0.

    Nathan -> Console -> MCP -> Kernel
    Clawde/OpenClaw -> MCP -> Kernel

The Console is userland. It holds a single long-lived MCP
ClientSession (spawned over stdio against mcp_server.py, a real
separate process) and every control below is a thin HTTP form around
one existing MCP-0 tool call. This module never imports kernel.py,
never imports sqlite3, and never opens a .db file itself -- see
console_0_4_no_direct_kernel_access.py, which asserts this
structurally by reading this file's own source (same technique as
mcp_0_3_no_direct_sqlite.py).

Deliberately excluded, per EASTER-CONSOLE-0's brief:
    - no canonical/current/preferred State is inferred or displayed
    - no branch is chosen on the operator's behalf
    - no Evidence is evaluated for truth or sufficiency
    - no State/Receipt/Grant payload is interpreted as Kernel meaning
      (payloads are shown as raw JSON, never parsed for application
      fields)
    - no automatic Authority policy (every write requires the
      operator to name the identity/grant/authority explicitly, same
      arguments MCP itself requires -- the Console never assumes
      "Nathan is root")
    - no retry/dedup of transitions
    - no orchestration, no agent memory

Exception retrieval and lineage/history inspection are not offered as
controls: MCP-0 has no supported operation for either (see
MCP_0_RECEIPT.md). Any Console page that would need one instead
records the exact unanswerable question -- see CONSOLE_0_RECEIPT.md.

Destructive/authority-changing actions (revoke, revoke_all) require
the operator to re-type the exact target id into a confirmation field.
A mismatch is rejected by the Console before any MCP call is made --
this is a userland safety gate, not a Kernel rule.
"""

from __future__ import annotations

import contextlib
import html
import json
import os
import sys
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).parent
MCP_SERVER_PATH = HERE / "mcp_server.py"


# ------------------------------------------------------------------
# MCP client plumbing: one shared ClientSession for the app lifetime.
# ------------------------------------------------------------------


class ConsoleMCPClient:
    """Owns the single long-lived MCP session the whole Console shares.

    mcp_server.py is spawned as a genuinely separate process over
    stdio -- the Console talks to it exactly the way any other MCP
    client would, including Clawde/OpenClaw. There is no in-process
    shortcut to the Kernel anywhere in this class.
    """

    def __init__(self, kernel_db_path: str | None) -> None:
        self._kernel_db_path = kernel_db_path
        self._stack: contextlib.AsyncExitStack | None = None
        self.session: ClientSession | None = None

    async def start(self) -> None:
        env = {"KERNEL_DB_PATH": self._kernel_db_path} if self._kernel_db_path else None
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SERVER_PATH)],
            cwd=str(HERE),
            env=env,
        )
        self._stack = contextlib.AsyncExitStack()
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        await self.session.initialize()

    async def stop(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def call(self, name: str, arguments: dict[str, Any]) -> tuple[bool, Any]:
        """Call an MCP-0 tool. Returns (is_error, parsed_json_or_text)."""
        assert self.session is not None, "ConsoleMCPClient not started"
        result = await self.session.call_tool(name, arguments)
        text = result.content[0].text if result.content else "null"
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = text
        return result.is_error, parsed


mcp_client = ConsoleMCPClient(os.environ.get("KERNEL_DB_PATH"))


# ------------------------------------------------------------------
# Tiny HTML helpers. No templating engine -- this is deliberately a
# small experimental cockpit, not a finished product.
# ------------------------------------------------------------------


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html><head><meta charset="utf-8"><title>EASTER Console -- {html.escape(title)}</title>
<style>
body {{ font-family: monospace; max-width: 760px; margin: 2rem auto; padding: 0 1rem; }}
nav a {{ margin-right: 1rem; }}
fieldset {{ margin-bottom: 1.5rem; }}
label {{ display: block; margin-top: 0.5rem; }}
input[type=text] {{ width: 100%; box-sizing: border-box; }}
pre {{ background: #f0f0f0; padding: 1rem; overflow-x: auto; white-space: pre-wrap; }}
.error {{ color: #a00; font-weight: bold; }}
.warn {{ color: #a60; }}
</style>
</head><body>
<h1>EASTER Console <small>(MCP-0 boundary only)</small></h1>
<nav>
  <a href="/">home</a>
  <a href="/state/genesis">genesis</a>
  <a href="/state">state</a>
  <a href="/receipt">receipt</a>
  <a href="/grant">grant</a>
  <a href="/authority/define">define authority</a>
  <a href="/grant/issue">issue grant</a>
  <a href="/grant/revoke">revoke grant</a>
  <a href="/grant/revoke-all">revoke all</a>
</nav>
<h2>{html.escape(title)}</h2>
{body}
</body></html>"""
    )


def result_block(is_error: bool, payload: Any) -> str:
    cls = "error" if is_error else ""
    label = "MCP tool error (Kernel rejected the call)" if is_error else "Result"
    pretty = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True)
    return f'<p class="{cls}"><strong>{label}:</strong></p><pre>{html.escape(pretty)}</pre>'


def lookup_form(action: str, field: str, label: str) -> str:
    return f"""
<form method="get" action="{action}">
  <label>{html.escape(label)}
    <input type="text" name="{field}" placeholder="{html.escape(field)}">
  </label>
  <button type="submit">Look up</button>
</form>
"""


# ------------------------------------------------------------------
# Read-only inspection: State, Receipt, Grant, Genesis.
# ------------------------------------------------------------------


async def home(request: Request) -> HTMLResponse:
    body = """
<p>This Console only reaches the Kernel through EASTER-MCP-0. It cannot
query SQLite, and it does not know or assume any "current" State,
"preferred" branch, or Authority policy -- every lookup and every
write names its own arguments explicitly, same as calling MCP
directly.</p>
<ul>
  <li><a href="/state/genesis">Inspect Genesis</a></li>
  <li><a href="/state">Inspect a known State</a></li>
  <li><a href="/receipt">Inspect a known Receipt</a></li>
  <li><a href="/grant">Inspect a known Grant</a></li>
  <li><a href="/authority/define">Define an Authority</a></li>
  <li><a href="/grant/issue">Issue a Grant</a></li>
  <li><a href="/grant/revoke">Revoke a Grant</a> (requires typed confirmation)</li>
  <li><a href="/grant/revoke-all">Revoke all Grants for an identity</a> (requires typed confirmation)</li>
</ul>
<p class="warn">Not offered: Exception retrieval, lineage/history
traversal, full graph enumeration -- EASTER-MCP-0 has no supported
operation for any of these. See CONSOLE_0_RECEIPT.md for the exact
questions this Console cannot answer as a result.</p>
"""
    return page("Home", body)


async def get_genesis_state(request: Request) -> HTMLResponse:
    is_error, result = await mcp_client.call("get_genesis_state", {})
    return page("Genesis State", result_block(is_error, result))


async def get_state(request: Request) -> HTMLResponse:
    state_id = request.query_params.get("state_id", "").strip()
    body = lookup_form("/state", "state_id", "state_id")
    if state_id:
        is_error, result = await mcp_client.call("get_state", {"state_id": state_id})
        body += result_block(is_error, result)
    return page("Inspect State", body)


async def get_receipt(request: Request) -> HTMLResponse:
    receipt_id = request.query_params.get("receipt_id", "").strip()
    body = lookup_form("/receipt", "receipt_id", "receipt_id")
    if receipt_id:
        is_error, result = await mcp_client.call("get_receipt", {"receipt_id": receipt_id})
        body += result_block(is_error, result)
    return page("Inspect Receipt", body)


async def get_grant(request: Request) -> HTMLResponse:
    grant_id = request.query_params.get("grant_id", "").strip()
    body = lookup_form("/grant", "grant_id", "grant_id")
    if grant_id:
        is_error, result = await mcp_client.call("get_grant", {"grant_id": grant_id})
        body += result_block(is_error, result)
    return page("Inspect Grant", body)


# ------------------------------------------------------------------
# Authority: define, issue grant, revoke, revoke_all.
#
# Every write form asks for requester_identity_id and
# authority_grant_id explicitly -- the Console never hardcodes or
# assumes "the operator is root". Whether the presented grant is
# actually valid and root is entirely the Kernel's decision, exactly
# as it is for any other MCP caller.
# ------------------------------------------------------------------


DEFINE_AUTHORITY_FORM = """
<form method="post" action="/authority/define">
  <fieldset>
    <legend>Define a new Authority (requires a currently valid root grant)</legend>
    <label>requester_identity_id <input type="text" name="requester_identity_id" required></label>
    <label>authority_grant_id (must be root) <input type="text" name="authority_grant_id" required></label>
    <label>authority_id (new) <input type="text" name="authority_id" required></label>
    <label><input type="checkbox" name="is_root" value="true"> is_root</label>
    <label>payload (JSON object, optional) <input type="text" name="payload" placeholder="{}"></label>
    <button type="submit">Define Authority</button>
  </fieldset>
</form>
"""

GRANT_ISSUE_FORM = """
<form method="post" action="/grant/issue">
  <fieldset>
    <legend>Issue a Grant (requires a currently valid root grant)</legend>
    <label>requester_identity_id <input type="text" name="requester_identity_id" required></label>
    <label>authority_grant_id (must be root) <input type="text" name="authority_grant_id" required></label>
    <label>identity_id (recipient) <input type="text" name="identity_id" required></label>
    <label>authority_id <input type="text" name="authority_id" required></label>
    <button type="submit">Issue Grant</button>
  </fieldset>
</form>
"""

GRANT_REVOKE_FORM = """
<form method="post" action="/grant/revoke">
  <fieldset>
    <legend>Revoke a Grant -- irreversible. Type grant_id twice.</legend>
    <label>requester_identity_id <input type="text" name="requester_identity_id" required></label>
    <label>authority_grant_id (must be root) <input type="text" name="authority_grant_id" required></label>
    <label>grant_id to revoke <input type="text" name="grant_id" required></label>
    <label>Type grant_id again to confirm <input type="text" name="confirm_grant_id" required></label>
    <label>reason (optional) <input type="text" name="reason"></label>
    <button type="submit">Revoke Grant</button>
  </fieldset>
</form>
"""

REVOKE_ALL_FORM = """
<form method="post" action="/grant/revoke-all">
  <fieldset>
    <legend>Revoke ALL Grants for an identity -- irreversible. Type identity_id twice.</legend>
    <label>requester_identity_id <input type="text" name="requester_identity_id" required></label>
    <label>authority_grant_id (must be root) <input type="text" name="authority_grant_id" required></label>
    <label>identity_id to revoke all grants for <input type="text" name="identity_id" required></label>
    <label>Type identity_id again to confirm <input type="text" name="confirm_identity_id" required></label>
    <label>reason (optional) <input type="text" name="reason"></label>
    <button type="submit">Revoke All Grants</button>
  </fieldset>
</form>
"""


async def define_authority_view(request: Request) -> HTMLResponse:
    return page("Define Authority", DEFINE_AUTHORITY_FORM)


async def define_authority_submit(request: Request) -> HTMLResponse:
    form = await request.form()
    payload_raw = (form.get("payload") or "").strip()
    payload = json.loads(payload_raw) if payload_raw else None
    is_error, result = await mcp_client.call(
        "define_authority",
        {
            "requester_identity_id": form.get("requester_identity_id"),
            "authority_grant_id": form.get("authority_grant_id"),
            "authority_id": form.get("authority_id"),
            "is_root": form.get("is_root") == "true",
            "payload": payload,
        },
    )
    return page("Define Authority -- result", DEFINE_AUTHORITY_FORM + result_block(is_error, result))


async def grant_issue_view(request: Request) -> HTMLResponse:
    return page("Issue Grant", GRANT_ISSUE_FORM)


async def grant_issue_submit(request: Request) -> HTMLResponse:
    form = await request.form()
    is_error, result = await mcp_client.call(
        "grant",
        {
            "requester_identity_id": form.get("requester_identity_id"),
            "authority_grant_id": form.get("authority_grant_id"),
            "identity_id": form.get("identity_id"),
            "authority_id": form.get("authority_id"),
        },
    )
    return page("Issue Grant -- result", GRANT_ISSUE_FORM + result_block(is_error, result))


async def grant_revoke_view(request: Request) -> HTMLResponse:
    return page("Revoke Grant", GRANT_REVOKE_FORM)


async def grant_revoke_submit(request: Request) -> HTMLResponse:
    form = await request.form()
    grant_id = (form.get("grant_id") or "").strip()
    confirm = (form.get("confirm_grant_id") or "").strip()

    if not grant_id or grant_id != confirm:
        body = (
            GRANT_REVOKE_FORM
            + '<p class="error">Confirmation did not match grant_id. '
            "Nothing was sent to the Kernel -- revocation requires deliberate, "
            "exact confirmation.</p>"
        )
        return page("Revoke Grant -- rejected by Console", body)

    is_error, result = await mcp_client.call(
        "revoke",
        {
            "requester_identity_id": form.get("requester_identity_id"),
            "authority_grant_id": form.get("authority_grant_id"),
            "grant_id": grant_id,
            "reason": (form.get("reason") or None),
        },
    )
    return page("Revoke Grant -- result", GRANT_REVOKE_FORM + result_block(is_error, result))


async def revoke_all_view(request: Request) -> HTMLResponse:
    return page("Revoke All Grants", REVOKE_ALL_FORM)


async def revoke_all_submit(request: Request) -> HTMLResponse:
    form = await request.form()
    identity_id = (form.get("identity_id") or "").strip()
    confirm = (form.get("confirm_identity_id") or "").strip()

    if not identity_id or identity_id != confirm:
        body = (
            REVOKE_ALL_FORM
            + '<p class="error">Confirmation did not match identity_id. '
            "Nothing was sent to the Kernel -- revoke_all requires deliberate, "
            "exact confirmation.</p>"
        )
        return page("Revoke All Grants -- rejected by Console", body)

    is_error, result = await mcp_client.call(
        "revoke_all",
        {
            "requester_identity_id": form.get("requester_identity_id"),
            "authority_grant_id": form.get("authority_grant_id"),
            "identity_id": identity_id,
            "reason": (form.get("reason") or None),
        },
    )
    return page("Revoke All Grants -- result", REVOKE_ALL_FORM + result_block(is_error, result))


routes = [
    Route("/", home),
    Route("/state/genesis", get_genesis_state),
    Route("/state", get_state),
    Route("/receipt", get_receipt),
    Route("/grant", get_grant),
    Route("/authority/define", define_authority_view, methods=["GET"]),
    Route("/authority/define", define_authority_submit, methods=["POST"]),
    Route("/grant/issue", grant_issue_view, methods=["GET"]),
    Route("/grant/issue", grant_issue_submit, methods=["POST"]),
    Route("/grant/revoke", grant_revoke_view, methods=["GET"]),
    Route("/grant/revoke", grant_revoke_submit, methods=["POST"]),
    Route("/grant/revoke-all", revoke_all_view, methods=["GET"]),
    Route("/grant/revoke-all", revoke_all_submit, methods=["POST"]),
]


@contextlib.asynccontextmanager
async def lifespan(app: Starlette):
    await mcp_client.start()
    try:
        yield
    finally:
        await mcp_client.stop()


app = Starlette(routes=routes, lifespan=lifespan)


if __name__ == "__main__":
    host = os.environ.get("CONSOLE_HOST", "127.0.0.1")
    port = int(os.environ.get("CONSOLE_PORT", "8420"))
    uvicorn.run(app, host=host, port=port, log_level="info")
