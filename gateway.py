#!/usr/bin/env python3
"""
EASTER-GATEWAY-0 -- Authenticated agent channel (skeleton).

    Agent --TLS--> gateway -> MCP stdio client -> mcp_server.py -> Kernel

This module is deliberately userland. It never imports ``kernel.py``,
never opens the kernel database, and never interprets Kernel payloads.
All kernel interaction goes through one MCP subprocess spawned from
``mcp_server.py``, exactly like EASTER-API-0
(see tests/gateway_0_1_skeleton.py, which asserts the no-direct-access
claim structurally by reading this file's own source -- same technique
as api_0_3_no_direct_kernel_access.py).

What this skeleton does:
  - TLS listener. Refuses to start without a certificate and key.
    Clients are expected to pin the certificate (fingerprint); a
    self-signed cert accepted without pinning is decoration, not
    security.
  - Bearer-token authentication. Tokens are opaque, high-entropy, and
    stored hashed (SHA-256) in a session file with 0600 permissions.
    The raw token is shown once at mint time and never stored.
  - Session binding. Every request's ``requester_identity_id`` is
    OVERWRITTEN with the session's identity -- callers never choose
    their identity. ``authority_grant_id`` must be a member of the
    session's grant set or the request is rejected (403) before MCP is
    ever called.
  - Per-role tool allowlist. The agent role cannot reach ``grant``,
    ``revoke``, ``revoke_all`` or ``define_authority`` through this
    gateway, ever. Those tools exist in no role.
  - Expired or invalid tokens are rejected (401/403) before MCP is
    ever called. A rejected token must not be able to grow the kernel's
    append-only store (receipt-spam): the kernel never sees it.

What it deliberately does NOT do yet (follow-up PRs):
  - Rate limiting / per-identity quotas.
  - Evidence lineage for token minting (auth events as Evidence).
  - mTLS / DPoP key binding for agent tokens.
  - A compromise button (today: delete the token from the session file,
    then revoke the kernel grant via the admin channel -- kernel first).

Human ceremony: there is no human-auth code path in this gateway.
Nathan-as-root mints and revokes agent tokens by running this module
locally (``python gateway.py mint ...``) over the admin channel
(loopback MCP / console). Host access IS human authentication.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import uvicorn
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

HERE = Path(__file__).parent
MCP_SERVER_PATH = HERE / "mcp_server.py"

DEFAULT_SESSIONS_PATH = Path.home() / ".easter" / "gateway_sessions.json"


# ------------------------------------------------------------------
# Time helpers (UTC, ISO-8601 Z -- same shape as the kernel's)
# ------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ------------------------------------------------------------------
# Session store: hashed opaque tokens, 0600 file, boring server-side
# ------------------------------------------------------------------

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionStore:
    """Maps token hashes -> session records. The raw token is never stored."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 0600: the session file is a credential store.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
        except BaseException:
            os.close(fd)
            raise
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def mint(
        self,
        *,
        identity_id: str,
        grant_ids: list[str],
        role: str,
        ttl_seconds: int,
        label: str = "",
    ) -> str:
        """Create a session, returning the raw token (shown once, never stored)."""
        if role not in ROLE_ALLOWLISTS:
            raise ValueError(f"unknown role: {role}")
        token = secrets.token_urlsafe(32)
        data = self._load()
        data[_token_hash(token)] = {
            "identity_id": identity_id,
            "grant_ids": sorted(set(grant_ids)),
            "role": role,
            "label": label,
            "created_at": _utc_now(),
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            ).isoformat().replace("+00:00", "Z"),
        }
        self._save(data)
        return token

    def revoke(self, token: str) -> bool:
        """Delete a session by raw token. Returns True if one existed."""
        data = self._load()
        digest = _token_hash(token)
        if digest not in data:
            return False
        del data[digest]
        self._save(data)
        return True

    def lookup(self, token: str) -> dict[str, Any] | None:
        """Return the live session for a raw token, or None.

        Expiry is enforced here: an expired session is treated exactly
        like an unknown token -- the kernel never sees the request.
        """
        data = self._load()
        session = data.get(_token_hash(token))
        if session is None:
            return None
        if _parse_ts(session["expires_at"]) <= datetime.now(timezone.utc):
            return None
        return session

    def list_sessions(self) -> list[dict[str, Any]]:
        data = self._load()
        out = []
        for digest, session in data.items():
            out.append(
                {
                    "token_prefix": digest[:12],
                    "identity_id": session["identity_id"],
                    "role": session["role"],
                    "label": session.get("label", ""),
                    "expires_at": session["expires_at"],
                }
            )
        return out


# ------------------------------------------------------------------
# Roles: what each session may reach. Admin tools exist in NO role.
# ------------------------------------------------------------------

READ_TOOLS = {
    "get_state",
    "get_genesis_state",
    "get_receipt",
    "get_grant",
    "get_identity",
    "get_authority",
    "get_evidence",
    "get_transition",
    "get_exception_by_receipt",
    "list_grants_for_identity",
    "list_transitions_from_state",
    "list_transitions_by_grant",
    "list_records",
}

WRITE_TOOLS = {
    "record_evidence",
    "transition",
}

# Tools that are reachable through NO gateway role, ever. They live on
# the admin channel (loopback MCP / console) only.
ADMIN_ONLY_TOOLS = {
    "grant",
    "revoke",
    "revoke_all",
    "define_authority",
}

ROLE_ALLOWLISTS: dict[str, set[str]] = {
    "reader": set(READ_TOOLS),
    "agent": set(READ_TOOLS) | set(WRITE_TOOLS),
}


# ------------------------------------------------------------------
# MCP client: one subprocess, one session, for the gateway lifetime.
# (Same shape as EASTER-API-0's MCPClient.)
# ------------------------------------------------------------------

class GatewayError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class MCPBackend:
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

    async def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        if self.session is None:
            raise GatewayError("MCP backend is not ready", 503)
        result = await self.session.call_tool(tool, arguments)
        if result.is_error:
            message = "MCP tool call failed"
            if result.content and hasattr(result.content[0], "text"):
                message = result.content[0].text
            raise GatewayError(message, 502)
        if not result.content:
            return None
        text = result.content[0].text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


# ------------------------------------------------------------------
# Request handling: authenticate, bind, forward.
# ------------------------------------------------------------------

def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _bind_arguments(
    session: dict[str, Any], tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Enforce the session binding. Returns the rewritten arguments.

    - requester_identity_id is OVERWRITTEN with the session identity.
      The caller never chooses who they are.
    - authority_grant_id, when the tool takes one, must be a member of
      the session's grant set. A foreign grant id is rejected here, at
      the gateway, before the kernel ever sees it.
    - identity_id query arguments (e.g. list_grants_for_identity) are
      forced to the session identity: one session cannot enumerate
      another identity's grants through this gateway.
    """
    bound = dict(arguments)

    if "requester_identity_id" in bound:
        bound["requester_identity_id"] = session["identity_id"]

    if "authority_grant_id" in bound:
        presented = bound["authority_grant_id"]
        if presented not in session["grant_ids"]:
            raise GatewayError(
                "authority_grant_id is not bound to this session", 403
            )

    if tool in {"list_grants_for_identity", "get_identity"} and "identity_id" in bound:
        bound["identity_id"] = session["identity_id"]

    return bound


def make_app(store: SessionStore, backend: MCPBackend) -> Starlette:
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "easter-gateway-0"})

    async def call_tool(request: Request) -> JSONResponse:
        tool = request.path_params["tool"]

        token = _bearer_token(request)
        if token is None:
            return JSONResponse({"error": "missing bearer token"}, status_code=401)
        session = store.lookup(token)
        if session is None:
            # Invalid OR expired: identical response, and the kernel
            # never sees the request (no receipt-spam surface).
            return JSONResponse(
                {"error": "invalid or expired token"}, status_code=403
            )

        if tool in ADMIN_ONLY_TOOLS:
            return JSONResponse(
                {"error": f"tool '{tool}' is not reachable via the gateway"},
                status_code=403,
            )
        if tool not in ROLE_ALLOWLISTS.get(session["role"], set()):
            return JSONResponse(
                {"error": f"tool '{tool}' is not allowed for role '{session['role']}'"},
                status_code=403,
            )

        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JSONResponse({"error": "request body must be valid JSON"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "request body must be a JSON object"}, status_code=400
            )

        try:
            bound = _bind_arguments(session, tool, body)
        except GatewayError as exc:
            return JSONResponse({"error": str(exc)}, status_code=exc.status)

        try:
            result = await backend.call(tool, bound)
        except GatewayError as exc:
            return JSONResponse({"error": str(exc)}, status_code=exc.status)
        return JSONResponse({"ok": True, "result": result})

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        await backend.start()
        try:
            yield
        finally:
            await backend.stop()

    return Starlette(
        lifespan=lifespan,  # type: ignore[arg-type]
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/tools/{tool}", call_tool, methods=["POST"]),
        ]
    )


# ------------------------------------------------------------------
# CLI: local ceremony for minting / revoking / listing tokens.
# ------------------------------------------------------------------

def _cli() -> None:
    parser = argparse.ArgumentParser(description="EASTER gateway-0 (skeleton)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the TLS gateway")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8443)
    p_serve.add_argument("--cert", required=True, help="TLS certificate file (PEM)")
    p_serve.add_argument("--key", required=True, help="TLS private key file (PEM)")
    p_serve.add_argument("--sessions", default=str(DEFAULT_SESSIONS_PATH))
    p_serve.add_argument("--kernel-db", default=os.environ.get("KERNEL_DB_PATH"))

    p_mint = sub.add_parser("mint", help="mint an agent token (local ceremony)")
    p_mint.add_argument("--identity", required=True)
    p_mint.add_argument("--grants", required=True, help="comma-separated grant ids")
    p_mint.add_argument("--role", default="agent", choices=sorted(ROLE_ALLOWLISTS))
    p_mint.add_argument("--ttl", type=int, default=3600, help="seconds")
    p_mint.add_argument("--label", default="")
    p_mint.add_argument("--sessions", default=str(DEFAULT_SESSIONS_PATH))

    p_revoke = sub.add_parser("revoke-token", help="revoke an agent token")
    p_revoke.add_argument("token")
    p_revoke.add_argument("--sessions", default=str(DEFAULT_SESSIONS_PATH))

    p_list = sub.add_parser("list", help="list sessions (hashes only)")
    p_list.add_argument("--sessions", default=str(DEFAULT_SESSIONS_PATH))

    args = parser.parse_args()

    if args.command == "serve":
        if not os.path.exists(args.cert) or not os.path.exists(args.key):
            print("refusing to start: --cert and --key are required", file=sys.stderr)
            sys.exit(2)
        store = SessionStore(args.sessions)
        backend = MCPBackend(args.kernel_db)
        app = make_app(store, backend)
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            ssl_certfile=args.cert,
            ssl_keyfile=args.key,
        )
        return

    store = SessionStore(args.sessions)
    if args.command == "mint":
        grant_ids = [g.strip() for g in args.grants.split(",") if g.strip()]
        token = store.mint(
            identity_id=args.identity,
            grant_ids=grant_ids,
            role=args.role,
            ttl_seconds=args.ttl,
            label=args.label,
        )
        print(token)
        print(
            "SHOWN ONCE: store this token with the agent. It is kept hashed server-side.",
            file=sys.stderr,
        )
    elif args.command == "revoke-token":
        print("revoked" if store.revoke(args.token) else "no such token")
    elif args.command == "list":
        for entry in store.list_sessions():
            print(json.dumps(entry, sort_keys=True))


if __name__ == "__main__":
    _cli()
