#!/usr/bin/env python3
"""EASTER-API-0 -- JSON HTTP adapter over the supported MCP surface.

    HTTP client -> API -> MCP stdio client -> mcp_server.py -> Kernel

This module is deliberately userland.  It never imports ``kernel.py`` or
``sqlite3`` and it does not interpret Kernel payloads.  Every operation below
is a thin HTTP mapping to one existing MCP tool, with the MCP arguments kept
unchanged in the JSON request body or query string.  See
api_0_3_no_direct_kernel_access.py, which asserts the no-direct-access claim
structurally by reading this file's own source (same technique as
mcp_0_3_no_direct_sqlite.py and console_0_4_no_direct_kernel_access.py).

Security model (loopback-only, same posture as EASTER-CONSOLE-0 -- no
authentication semantics are invented anywhere, and none live in the
Kernel):
    - The API is constrained to loopback-only operation, enforced at two
      layers: ``python api_server.py`` refuses a non-loopback API_HOST at
      startup, and LoopbackOnlyMiddleware rejects (403) any HTTP request whose
      peer address is not loopback before any route runs. The second layer is
      what keeps ``uvicorn api_server:app --host 0.0.0.0`` -- which never
      executes the startup check -- from exposing the API. The supported
      launch is ``python api_server.py``; see api_0_6_loopback_launch_contract.py.
    - Every state-changing POST (record_evidence, transition,
      define_authority, grant, revoke, revoke_all) is rejected with 403
      before MCP is ever called if its Origin (or, when Origin is absent,
      Referer) header does not match this API's own loopback origin -- see
      reject_cross_origin(). Binding to loopback alone does not stop a
      malicious cross-origin page from submitting a matching request to
      this API on the operator's behalf, including via a
      non-preflighted "simple" request (e.g. Content-Type: text/plain,
      which browsers never send a CORS preflight for). See
      api_0_2_csrf_origin_protection.py for adversarial proof, including
      the non-preflighted case, on all six routes.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

HERE = Path(__file__).parent
MCP_SERVER_PATH = HERE / "mcp_server.py"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class APIError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _is_loopback_client(client: tuple[str, int] | None) -> bool:
    """True only for a peer address that is a numeric loopback IP."""
    if not client:
        return False
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        return False
    return (getattr(address, "ipv4_mapped", None) or address).is_loopback


class LoopbackOnlyMiddleware:
    """Reject any HTTP request whose peer is not a loopback address.

    Enforces the loopback-only contract at the application boundary, so it
    holds however the ASGI app is launched (``uvicorn api_server:app --host
    0.0.0.0`` included), not just under ``python api_server.py``.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and not _is_loopback_client(scope.get("client")):
            response = JSONResponse(
                {"error": "Rejected: EASTER-API-0 accepts loopback clients only."},
                status_code=403,
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class MCPClient:
    """Own one MCP subprocess and one session for the API lifetime."""

    def __init__(self, kernel_db_path: str | None) -> None:
        self._kernel_db_path = kernel_db_path
        self._stack: contextlib.AsyncExitStack | None = None
        self.session: ClientSession | None = None
        self._call_lock = asyncio.Lock()

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
            raise APIError("MCP session is not ready", 503)
        async with self._call_lock:
            result = await self.session.call_tool(tool, arguments)
        if result.is_error:
            message = "MCP tool call failed"
            if result.content and hasattr(result.content[0], "text"):
                message = result.content[0].text
            raise APIError(message)
        if not result.content:
            return None
        text = result.content[0].text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


mcp_client = MCPClient(os.environ.get("KERNEL_DB_PATH"))


async def json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise APIError("request body must be valid JSON") from exc
    if not isinstance(body, dict):
        raise APIError("request body must be a JSON object")
    return body


def _allowed_origins(request: Request) -> set[str]:
    """This API's own loopback origin(s), for the port actually in use."""
    port = request.url.port
    scheme = request.url.scheme
    return {f"{scheme}://{host}:{port}" for host in LOOPBACK_HOSTS}


def _referer_origin(referer: str) -> str | None:
    """Extract an exact scheme/host/port origin from a Referer URL."""
    try:
        parsed = urlsplit(referer)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        hostname = parsed.hostname
        if hostname is None:
            return None
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        return f"{parsed.scheme}://{hostname}:{port}"
    except ValueError:
        return None


def reject_cross_origin(request: Request) -> None:
    """CSRF/cross-origin guard for state-changing POSTs.

    Same technique as console.reject_cross_origin: binding to loopback
    alone does nothing to stop a malicious cross-origin page from
    submitting a matching request to this API on the operator's behalf,
    including a non-preflighted "simple" request (e.g. a fetch() with
    Content-Type: text/plain, which browsers never preflight, carrying a
    JSON-encoded body Starlette parses the same as application/json).

    Raises APIError(403) *before* any MCP call is made if the request's
    Origin (or, when Origin is absent, Referer) header does not match this
    API's own loopback origin. Raises nothing if the request should
    proceed.

    A request with neither Origin nor Referer at all is treated as
    first-party tooling (curl, direct API scripts, this repo's own test
    scripts) rather than a browser-driven cross-origin attack: real
    browsers reliably attach Origin to state-changing cross-origin
    requests, so its complete absence is not the attack this check exists
    to stop.
    """
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    allowed = _allowed_origins(request)

    if origin is not None and origin not in allowed:
        raise APIError(
            f"Rejected before contacting MCP: Origin {origin!r} does not "
            "match this API's own loopback origin.",
            status_code=403,
        )
    if origin is None and referer is not None and _referer_origin(referer) not in allowed:
        raise APIError(
            f"Rejected before contacting MCP: Referer {referer!r} does not "
            "match this API's own loopback origin.",
            status_code=403,
        )


def path_list_arguments(request: Request, required_name: str) -> dict[str, Any]:
    args = {required_name: request.path_params[required_name]}
    for name in ("after", "limit"):
        value = request.query_params.get(name)
        if value is not None and value != "":
            if name == "limit":
                try:
                    args[name] = int(value)
                except ValueError as exc:
                    raise APIError("limit must be an integer") from exc
            else:
                args[name] = value
    return args


async def call_tool(request: Request, tool: str, arguments: dict[str, Any]) -> JSONResponse:
    return JSONResponse(await mcp_client.call(tool, arguments))


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "easter-api-0"})


_JSON_TYPES: dict[str, dict[str, Any]] = {
    "string": {"type": "string"},
    "object": {"type": "object"},
    "boolean": {"type": "boolean"},
    "strings": {"type": "array", "items": {"type": "string"}},
    "objects": {"type": "array", "items": {"type": "object"}},
}

# Request-body arguments per write operation: name -> (JSON type, required).
# These are the MCP tool arguments unchanged, except revoke's grant_id, which
# is carried by the URL path only.
_WRITE_BODIES: dict[str, dict[str, tuple[str, str]]] = {
    "record_evidence": {
        "requester_identity_id": ("string", "required"),
        "authority_grant_id": ("string", "required"),
        "payload": ("object", "required"),
    },
    "transition": {
        "requester_identity_id": ("string", "required"),
        "from_state_id": ("string", "required"),
        "authority_grant_id": ("string", "required"),
        "new_state_payload": ("object", "required"),
        "transition_payload": ("object", "nullable"),
        "evidence_ids": ("strings", "nullable"),
        "new_identities": ("objects", "nullable"),
    },
    "define_authority": {
        "requester_identity_id": ("string", "required"),
        "authority_grant_id": ("string", "required"),
        "authority_id": ("string", "required"),
        "is_root": ("boolean", "optional"),
        "payload": ("object", "nullable"),
        "evidence_ids": ("strings", "nullable"),
    },
    "grant": {
        "requester_identity_id": ("string", "required"),
        "authority_grant_id": ("string", "required"),
        "identity_id": ("string", "required"),
        "authority_id": ("string", "required"),
        "valid_from": ("string", "nullable"),
        "expires_at": ("string", "nullable"),
        "payload": ("object", "nullable"),
        "evidence_ids": ("strings", "nullable"),
    },
    "revoke": {
        "requester_identity_id": ("string", "required"),
        "authority_grant_id": ("string", "required"),
        "reason": ("string", "nullable"),
        "evidence_ids": ("strings", "nullable"),
    },
    "revoke_all": {
        "requester_identity_id": ("string", "required"),
        "authority_grant_id": ("string", "required"),
        "identity_id": ("string", "required"),
        "reason": ("string", "nullable"),
        "evidence_ids": ("strings", "nullable"),
    },
}

# (HTTP method, path template, MCP tool, paginated). Path parameters are the
# template's {names}; this table mirrors ``routes`` below and is checked
# against it and against the MCP tool list by api_0_5_openapi_contract.py.
_OPERATIONS: list[tuple[str, str, str, bool]] = [
    ("get", "/v1/state/genesis", "get_genesis_state", False),
    ("get", "/v1/state/{state_id}", "get_state", False),
    ("post", "/v1/evidence", "record_evidence", False),
    ("post", "/v1/transitions", "transition", False),
    ("get", "/v1/receipts/{receipt_id}", "get_receipt", False),
    ("get", "/v1/receipts/{receipt_id}/exception", "get_exception_by_receipt", False),
    ("get", "/v1/grants/{grant_id}", "get_grant", False),
    ("post", "/v1/grants", "grant", False),
    ("post", "/v1/grants/{grant_id}/revoke", "revoke", False),
    ("post", "/v1/grants/revoke-all", "revoke_all", False),
    ("post", "/v1/authorities", "define_authority", False),
    ("get", "/v1/identities/{identity_id}", "get_identity", False),
    ("get", "/v1/authorities/{authority_id}", "get_authority", False),
    ("get", "/v1/evidence/{evidence_id}", "get_evidence", False),
    ("get", "/v1/transitions/{transition_id}", "get_transition", False),
    ("get", "/v1/identities/{identity_id}/grants", "list_grants_for_identity", True),
    ("get", "/v1/states/{state_id}/transitions", "list_transitions_from_state", True),
    ("get", "/v1/grants/{authority_grant_id}/transitions", "list_transitions_by_grant", True),
    ("get", "/v1/records/{record_type}", "list_records", True),
]


def _build_openapi_document() -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    for method, template, tool, paginated in _OPERATIONS:
        parameters: list[dict[str, Any]] = [
            {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
            for name in re.findall(r"{([a-z_]+)}", template)
        ]
        if paginated:
            parameters.append({"name": "after", "in": "query", "required": False, "schema": {"type": "string"}})
            parameters.append({"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}})
        operation: dict[str, Any] = {"operationId": tool, "parameters": parameters}
        if tool in _WRITE_BODIES:
            body = _WRITE_BODIES[tool]
            schema: dict[str, Any] = {
                "type": "object",
                "properties": {
                    name: ({**_JSON_TYPES[kind], "nullable": True} if presence == "nullable" else dict(_JSON_TYPES[kind]))
                    for name, (kind, presence) in body.items()
                },
                "required": [name for name, (_, presence) in body.items() if presence == "required"],
            }
            operation["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": schema}},
            }
        operation["responses"] = {
            "200": {
                "description": "The MCP tool result, unchanged.",
                "content": {"application/json": {"schema": {}}},
            },
            "400": {"$ref": "#/components/responses/Error"},
            "403": {"$ref": "#/components/responses/Forbidden"},
        }
        paths.setdefault(template, {})[method] = operation
    error_schema = {"$ref": "#/components/schemas/Error"}
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "EASTER API",
            "version": "0",
            "description": (
                "HTTP/JSON projection of the frozen 19-operation EASTER MCP v0.2 "
                "surface. Arguments and results are the MCP tool arguments and "
                "results unchanged; pagination cursors (`after`) are opaque."
            ),
        },
        "paths": paths,
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}},
                    "required": ["error"],
                }
            },
            "responses": {
                "Error": {
                    "description": "The request or the MCP tool call was rejected.",
                    "content": {"application/json": {"schema": error_schema}},
                },
                "Forbidden": {
                    "description": (
                        "Rejected before contacting MCP: non-loopback client, or a "
                        "cross-origin Origin/Referer on a state-changing request."
                    ),
                    "content": {"application/json": {"schema": error_schema}},
                },
            },
        },
    }


OPENAPI_DOCUMENT = _build_openapi_document()


async def openapi(request: Request) -> JSONResponse:
    """Serve the OpenAPI 3.0.3 description of the 19 frozen operations."""
    return JSONResponse(OPENAPI_DOCUMENT)


async def tool_from_body(request: Request, tool: str) -> JSONResponse:
    reject_cross_origin(request)
    return await call_tool(request, tool, await json_body(request))


async def revoke_grant(request: Request) -> JSONResponse:
    reject_cross_origin(request)
    arguments = await json_body(request)
    if "grant_id" in arguments:
        raise APIError("grant_id is identified by the URL path and must not appear in the request body")
    arguments["grant_id"] = request.path_params["grant_id"]
    return await call_tool(request, "revoke", arguments)


async def path_get(request: Request, tool: str, parameter: str) -> JSONResponse:
    return await call_tool(request, tool, {parameter: request.path_params[parameter]})


def tool_endpoint(tool: str):
    async def endpoint(request: Request) -> JSONResponse:
        return await tool_from_body(request, tool)

    return endpoint


def getter_endpoint(tool: str, parameter: str):
    async def endpoint(request: Request) -> JSONResponse:
        return await path_get(request, tool, parameter)

    return endpoint


def empty_tool_endpoint(tool: str):
    async def endpoint(request: Request) -> JSONResponse:
        return await call_tool(request, tool, {})

    return endpoint


async def list_grants(request: Request) -> JSONResponse:
    return await call_tool(request, "list_grants_for_identity", path_list_arguments(request, "identity_id"))


async def list_transitions_from_state(request: Request) -> JSONResponse:
    return await call_tool(request, "list_transitions_from_state", path_list_arguments(request, "state_id"))


async def list_transitions_by_grant(request: Request) -> JSONResponse:
    return await call_tool(request, "list_transitions_by_grant", path_list_arguments(request, "authority_grant_id"))


async def list_records(request: Request) -> JSONResponse:
    return await call_tool(request, "list_records", path_list_arguments(request, "record_type"))


async def get_state(request: Request) -> JSONResponse:
    return await path_get(request, "get_state", "state_id")


async def exception_for_receipt(request: Request) -> JSONResponse:
    return await path_get(request, "get_exception_by_receipt", "receipt_id")


async def handle_api_error(request: Request, exc: APIError) -> JSONResponse:
    return JSONResponse({"error": exc.message}, status_code=exc.status_code)


routes = [
    Route("/healthz", healthz),
    Route("/openapi.json", openapi),
    Route("/v1/state/genesis", empty_tool_endpoint("get_genesis_state")),
    Route("/v1/state/{state_id}", get_state),
    Route("/v1/evidence", tool_endpoint("record_evidence"), methods=["POST"]),
    Route("/v1/transitions", tool_endpoint("transition"), methods=["POST"]),
    Route("/v1/receipts/{receipt_id}/exception", exception_for_receipt),
    Route("/v1/receipts/{receipt_id}", getter_endpoint("get_receipt", "receipt_id")),
    Route("/v1/grants/revoke-all", tool_endpoint("revoke_all"), methods=["POST"]),
    Route("/v1/grants/{grant_id}/revoke", revoke_grant, methods=["POST"]),
    Route("/v1/authorities", tool_endpoint("define_authority"), methods=["POST"]),
    Route("/v1/grants", tool_endpoint("grant"), methods=["POST"]),
    Route("/v1/identities/{identity_id}/grants", list_grants),
    Route("/v1/states/{state_id}/transitions", list_transitions_from_state),
    Route("/v1/grants/{authority_grant_id}/transitions", list_transitions_by_grant),
    Route("/v1/grants/{grant_id}", getter_endpoint("get_grant", "grant_id")),
    Route("/v1/records/{record_type}", list_records),
    Route("/v1/identities/{identity_id}", getter_endpoint("get_identity", "identity_id")),
    Route("/v1/authorities/{authority_id}", getter_endpoint("get_authority", "authority_id")),
    Route("/v1/evidence/{evidence_id}", getter_endpoint("get_evidence", "evidence_id")),
    Route("/v1/transitions/{transition_id}", getter_endpoint("get_transition", "transition_id")),
]


@contextlib.asynccontextmanager
async def lifespan(app: Starlette):
    await mcp_client.start()
    try:
        yield
    finally:
        await mcp_client.stop()


app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[Middleware(LoopbackOnlyMiddleware)],
    exception_handlers={APIError: handle_api_error},
)


if __name__ == "__main__":
    host = os.environ.get("API_HOST", "127.0.0.1")
    if host not in LOOPBACK_HOSTS:
        raise SystemExit(
            f"API_HOST={host!r} rejected: EASTER-API-0 is loopback-only until "
            "remote authentication and authorization are designed."
        )
    port = int(os.environ.get("API_PORT", "8430"))
    uvicorn.run(app, host=host, port=port, log_level="info")
