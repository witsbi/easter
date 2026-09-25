"""EASTER-API-0 structural check: /openapi.json is a valid OpenAPI 3.0.3
document whose operation set is exactly the frozen 19-operation MCP v0.2
surface.

Checked, against the real server and the real MCP server:

  1. The MCP server's tool list is still the frozen 19 (FROZEN_OPERATIONS
     below is the contract's own list, not derived from the API).
  2. The served /openapi.json is structurally valid OpenAPI 3.0.3 (required
     objects present, every $ref resolves, every path template parameter is
     declared as a required path parameter, every operation has responses,
     schemas are well formed). If openapi-spec-validator happens to be
     installed it is run as well; it is not a dependency of this repo.
  3. The documented operationIds are exactly the frozen 19, once each.
  4. The documented (method, path) pairs are exactly the API's real route
     table (excluding the /healthz and /openapi.json infrastructure routes).
  5. Per operation, path parameters + query parameters + request-body
     properties are exactly the MCP tool's input properties, the required set
     matches the MCP tool's required set, and each body property's
     nullability matches the MCP schema -- so the HTTP document cannot drift
     from, or reinterpret, an MCP argument.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

FROZEN_OPERATIONS = {
    # v0.1
    "get_state",
    "get_genesis_state",
    "record_evidence",
    "transition",
    "get_receipt",
    "get_grant",
    "define_authority",
    "grant",
    "revoke",
    "revoke_all",
    # v0.2 observability
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

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
SCHEMA_TYPES = {"string", "number", "integer", "boolean", "array", "object"}
INFRASTRUCTURE_PATHS = {"/healthz", "/openapi.json"}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def mcp_input_schemas(db_path: str) -> dict[str, dict[str, Any]]:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "mcp_server.py")],
        env={"KERNEL_DB_PATH": db_path},
        cwd=str(HERE),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return {tool.name: tool.input_schema for tool in (await session.list_tools()).tools}


def resolve(doc: dict[str, Any], ref: str) -> Any:
    assert ref.startswith("#/"), f"only local $refs are used, got {ref!r}"
    node: Any = doc
    for part in ref[2:].split("/"):
        assert isinstance(node, dict) and part in node, f"unresolvable $ref {ref!r}"
        node = node[part]
    return node


def check_schema(doc: dict[str, Any], schema: Any, where: str) -> None:
    assert isinstance(schema, dict), f"{where}: schema must be an object"
    if "$ref" in schema:
        resolve(doc, schema["$ref"])
        return
    if "type" in schema:
        assert schema["type"] in SCHEMA_TYPES, f"{where}: bad type {schema['type']!r}"
    if "nullable" in schema:
        assert isinstance(schema["nullable"], bool) and "type" in schema, f"{where}: bad nullable"
    if schema.get("type") == "array":
        assert "items" in schema, f"{where}: array schema needs items"
    if "items" in schema:
        check_schema(doc, schema["items"], f"{where}.items")
    properties = schema.get("properties", {})
    for name, sub in properties.items():
        check_schema(doc, sub, f"{where}.{name}")
    for name in schema.get("required", []):
        assert name in properties, f"{where}: required {name!r} is not a property"


def check_responses(doc: dict[str, Any], responses: Any, where: str) -> None:
    assert isinstance(responses, dict) and responses, f"{where}: responses is required and non-empty"
    for code, response in responses.items():
        assert re.fullmatch(r"[1-5][0-9X]{2}|default", code), f"{where}: bad status key {code!r}"
        if "$ref" in response:
            response = resolve(doc, response["$ref"])
        assert isinstance(response.get("description"), str), f"{where}.{code}: description is required"
        for media, body in response.get("content", {}).items():
            check_schema(doc, body.get("schema", {}), f"{where}.{code}.{media}")


def validate_openapi_303(doc: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Structural OpenAPI 3.0.3 validation; returns [(method, path, operation)]."""
    assert doc.get("openapi") == "3.0.3", doc.get("openapi")
    info = doc.get("info")
    assert isinstance(info, dict) and isinstance(info.get("title"), str) and isinstance(info.get("version"), str)
    paths = doc.get("paths")
    assert isinstance(paths, dict) and paths, "paths is required and non-empty"

    for group in ("schemas", "responses"):
        for name, item in doc.get("components", {}).get(group, {}).items():
            assert re.fullmatch(r"[A-Za-z0-9._-]+", name), f"bad component name {name!r}"
            if group == "schemas":
                check_schema(doc, item, f"components.schemas.{name}")
            else:
                check_responses(doc, {"default": item}, f"components.responses.{name}")

    operations: list[tuple[str, str, dict[str, Any]]] = []
    operation_ids: set[str] = set()
    for path, item in paths.items():
        assert path.startswith("/"), f"path must start with '/': {path!r}"
        template_params = re.findall(r"{([^}/]+)}", path)
        for method, operation in item.items():
            assert method in HTTP_METHODS, f"{path}: unexpected key {method!r}"
            where = f"{method.upper()} {path}"
            operation_id = operation.get("operationId")
            assert isinstance(operation_id, str) and operation_id not in operation_ids, f"{where}: operationId"
            operation_ids.add(operation_id)

            seen: set[tuple[str, str]] = set()
            path_params: list[str] = []
            for parameter in operation.get("parameters", []):
                assert parameter["in"] in {"path", "query", "header", "cookie"}, where
                key = (parameter["name"], parameter["in"])
                assert key not in seen, f"{where}: duplicate parameter {key}"
                seen.add(key)
                assert "schema" in parameter, f"{where}: parameter {key} needs a schema"
                check_schema(doc, parameter["schema"], f"{where} parameter {key}")
                if parameter["in"] == "path":
                    assert parameter.get("required") is True, f"{where}: path parameter must be required"
                    path_params.append(parameter["name"])
            assert sorted(path_params) == sorted(template_params), (
                f"{where}: path template params {template_params} != declared {path_params}"
            )

            if "requestBody" in operation:
                assert method in {"post", "put", "patch"}, f"{where}: requestBody not allowed"
                content = operation["requestBody"].get("content")
                assert isinstance(content, dict) and content, f"{where}: requestBody.content"
                for media, body in content.items():
                    check_schema(doc, body["schema"], f"{where} requestBody {media}")
            check_responses(doc, operation.get("responses"), where)
            operations.append((method, path, operation))
    return operations


def body_schema(operation: dict[str, Any]) -> dict[str, Any]:
    if "requestBody" not in operation:
        return {}
    return operation["requestBody"]["content"]["application/json"]["schema"]


def main() -> None:
    import api_server

    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="api-0-openapi-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)

        # 1. The MCP surface is still the frozen 19.
        mcp_schemas = asyncio.run(mcp_input_schemas(str(db_path)))
        assert set(mcp_schemas) == FROZEN_OPERATIONS, (
            f"MCP surface drifted from the frozen 19: "
            f"missing={sorted(FROZEN_OPERATIONS - set(mcp_schemas))} "
            f"extra={sorted(set(mcp_schemas) - FROZEN_OPERATIONS)}"
        )
        assert len(FROZEN_OPERATIONS) == 19

        port = free_port()
        env = os.environ.copy()
        env.update({"KERNEL_DB_PATH": str(db_path), "API_PORT": str(port)})
        process = subprocess.Popen(
            [sys.executable, str(HERE / "api_server.py")], cwd=HERE, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            url = f"http://127.0.0.1:{port}/openapi.json"
            deadline = time.time() + 15
            while True:
                try:
                    with urllib.request.urlopen(url, timeout=2) as response:
                        assert response.status == 200
                        assert response.headers.get_content_type() == "application/json"
                        doc = json.loads(response.read())
                    break
                except OSError:
                    if time.time() > deadline:
                        raise
                    time.sleep(0.1)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    # 2. Valid OpenAPI 3.0.3 (structural, plus the real validator if present).
    operations = validate_openapi_303(doc)
    external = "not installed (structural validation only)"
    try:
        from openapi_spec_validator import validate  # type: ignore[import-not-found]

        validate(doc)
        external = "openapi-spec-validator: valid"
    except ImportError:
        pass

    # 3. Exactly the frozen 19 operations, once each.
    operation_ids = [operation["operationId"] for _, _, operation in operations]
    assert len(operation_ids) == len(set(operation_ids)) == 19, operation_ids
    assert set(operation_ids) == FROZEN_OPERATIONS, (
        f"documented operations differ from the frozen 19: "
        f"missing={sorted(FROZEN_OPERATIONS - set(operation_ids))} "
        f"extra={sorted(set(operation_ids) - FROZEN_OPERATIONS)}"
    )

    # 4. Documented (method, path) pairs are exactly the real route table.
    route_pairs = {
        (method.lower(), route.path)
        for route in api_server.routes
        if route.path not in INFRASTRUCTURE_PATHS
        for method in (route.methods or set()) - {"HEAD"}
    }
    documented_pairs = {(method, path) for method, path, _ in operations}
    assert documented_pairs == route_pairs, (
        f"documented != routes: only-documented={sorted(documented_pairs - route_pairs)} "
        f"only-routed={sorted(route_pairs - documented_pairs)}"
    )

    # 5. Arguments per operation are exactly the MCP tool's arguments.
    for method, path, operation in operations:
        tool = operation["operationId"]
        mcp = mcp_schemas[tool]
        mcp_props = set(mcp.get("properties", {}))
        mcp_required = set(mcp.get("required", []))

        parameters = operation.get("parameters", [])
        path_names = {p["name"] for p in parameters if p["in"] == "path"}
        query_names = {p["name"] for p in parameters if p["in"] == "query"}
        body = body_schema(operation)
        body_props = set(body.get("properties", {}))
        body_required = set(body.get("required", []))

        pieces = [path_names, query_names, body_props]
        assert sum(len(piece) for piece in pieces) == len(path_names | query_names | body_props), (
            f"{tool}: an MCP argument is represented in more than one place: {pieces}"
        )
        assert path_names | query_names | body_props == mcp_props, (
            f"{tool}: documented arguments {sorted(path_names | query_names | body_props)} "
            f"!= MCP arguments {sorted(mcp_props)}"
        )
        assert path_names | body_required == mcp_required, (
            f"{tool}: documented required {sorted(path_names | body_required)} "
            f"!= MCP required {sorted(mcp_required)}"
        )
        for name, schema in body.get("properties", {}).items():
            mcp_nullable = any(option.get("type") == "null" for option in mcp["properties"][name].get("anyOf", []))
            assert schema.get("nullable", False) == mcp_nullable, f"{tool}.{name}: nullability differs from MCP"
        if method == "get":
            assert "requestBody" not in operation, f"{tool}: GET must not have a body"

    # grant_id is represented once for revoke: the URL path, never the body.
    revoke = next(op for _, _, op in operations if op["operationId"] == "revoke")
    assert "grant_id" not in body_schema(revoke)["properties"]
    assert any(p["name"] == "grant_id" and p["in"] == "path" for p in revoke["parameters"])

    print("api_0_5_openapi_contract: OK")
    print("  MCP surface == frozen 19 operations")
    print("  /openapi.json: valid OpenAPI 3.0.3 (structural check); external validator:", external)
    print("  documented operations == frozen 19 == real route table (excl. /healthz, /openapi.json)")
    print("  per-operation arguments, required set and nullability == MCP tool input schemas")


if __name__ == "__main__":
    main()
