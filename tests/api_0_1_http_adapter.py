"""EASTER-API-0 black-box checks.

Starts the real HTTP server, which starts the real MCP stdio subprocess, and
checks representative read, list, write, and error mappings against a
throwaway copy of the reference database.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port: int, method: str, path: str, body: object | None = None) -> tuple[int, object]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as response:
        return response.code, json.loads(response.read())


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="easter-api-0-", suffix=".db") as f:
        db_path = Path(f.name)
        f.close()
        shutil.copy2(source, db_path)
        port = free_port()
        env = os.environ.copy()
        env.update({"KERNEL_DB_PATH": str(db_path), "API_PORT": str(port)})
        process = subprocess.Popen([sys.executable, str(HERE / "api_server.py")], cwd=HERE, env=env)
        try:
            deadline = time.time() + 15
            while time.time() < deadline:
                try:
                    status, value = request(port, "GET", "/healthz")
                    if status == 200 and value["status"] == "ok":
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise AssertionError("API server did not become ready")

            status, genesis = request(port, "GET", "/v1/state/genesis")
            assert status == 200 and genesis["state_id"] == "state:genesis", genesis

            status, schema = request(port, "GET", "/openapi.json")
            assert status == 200 and "/v1/transitions" in schema["paths"], schema

            status, records = request(port, "GET", "/v1/records/grant?limit=1")
            assert status == 200 and records["items"], records

            status, grants = request(port, "GET", "/v1/identities/identity:nathan/grants?limit=1")
            assert status == 200 and grants["items"], grants

            status, evidence = request(
                port,
                "POST",
                "/v1/evidence",
                {
                    "requester_identity_id": "identity:nathan",
                    "authority_grant_id": "grant:genesis-root",
                    "payload": {"probe": "easter-api-0"},
                },
            )
            assert status == 200 and evidence["evidence_id"].startswith("evidence:"), evidence

            status, error = request(port, "GET", "/v1/records/grant?limit=not-an-int")
            assert status == 400 and "limit" in error["error"], error

            status, error = request(port, "POST", "/v1/evidence", {"unexpected": "arguments"})
            assert status == 400 and "validation" in error["error"].lower(), error
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
