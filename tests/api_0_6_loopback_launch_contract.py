"""EASTER-API-0 launch contract: loopback-only holds however the app is
launched, not just under ``python api_server.py``.

The supported launch is ``python api_server.py``, which refuses a
non-loopback API_HOST at startup. But ``uvicorn api_server:app --host
0.0.0.0`` imports the ASGI app directly and never runs that startup check, so
the bind-host guard alone can be bypassed. The application-boundary guard
(LoopbackOnlyMiddleware) rejects any HTTP request whose peer address is not a
loopback IP with 403, before any route -- and therefore before MCP -- runs.

Proven three ways:

  1. Startup: ``python api_server.py`` with API_HOST=0.0.0.0 exits non-zero.
  2. ASGI level (deterministic, no network needed): the real ``app`` answers
     loopback peers normally and rejects every non-loopback / malformed peer
     on every kind of route.
  3. Live bypass reproduction: ``uvicorn api_server:app --host 0.0.0.0`` is
     started, then requested from a genuinely non-loopback local address
     (this host's own LAN address). Reads and a state-changing POST are all
     rejected, and the POST demonstrably never reaches the Kernel (evidence
     row count unchanged), while loopback requests to the same process still
     succeed. Skipped, loudly, only if the host has no non-loopback address.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

REJECTION = {"error": "Rejected: EASTER-API-0 accepts loopback clients only."}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def non_loopback_address() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))
            address = sock.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("127.") else address


async def asgi_request(app: Any, method: str, path: str, client: Any) -> tuple[int, bytes]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8430")],
        "client": client,
        "server": ("127.0.0.1", 8430),
    }
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, body


def http(url: str, method: str = "GET", body: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"} if data else {}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def check_startup_refusal() -> None:
    env = dict(os.environ, API_HOST="0.0.0.0", API_PORT=str(free_port()), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, str(HERE / "api_server.py")],
        cwd=HERE, env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0, "non-loopback API_HOST must be refused at startup"
    assert "loopback-only" in (result.stderr + result.stdout), result.stderr


def check_asgi_boundary() -> None:
    import api_server

    app = api_server.app
    allowed = [
        ("127.0.0.1", 50000),
        ("127.0.0.2", 50000),
        ("::1", 50000, 0, 0),
        ("::ffff:127.0.0.1", 50000, 0, 0),
    ]
    for client in allowed:
        status, body = asyncio.run(asgi_request(app, "GET", "/healthz", client))
        assert status == 200 and json.loads(body)["status"] == "ok", (client, status, body)

    denied = [
        ("192.168.1.10", 50000),
        ("10.0.0.5", 50000),
        ("8.8.8.8", 50000),
        ("::ffff:192.168.1.10", 50000, 0, 0),
        ("fe80::1", 50000, 0, 0),
        ("localhost", 50000),
        ("testclient", 50000),
        ("", 0),
        None,
    ]
    routes = [
        ("GET", "/healthz"),
        ("GET", "/openapi.json"),
        ("GET", "/v1/state/genesis"),
        ("POST", "/v1/evidence"),
        ("POST", "/v1/grants/revoke-all"),
    ]
    for client in denied:
        for method, path in routes:
            status, body = asyncio.run(asgi_request(app, method, path, client))
            assert status == 403 and json.loads(body) == REJECTION, (client, method, path, status, body)


def check_uvicorn_bypass_is_closed() -> str:
    address = non_loopback_address()
    if address is None:
        return "SKIPPED live probe: no non-loopback address on this host (ASGI-level proof above still holds)"

    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="api-0-loopback-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)
        port = free_port()
        env = dict(os.environ, KERNEL_DB_PATH=str(db_path), PYTHONDONTWRITEBYTECODE="1")
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", str(port)],
            cwd=HERE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 20
            while True:
                try:
                    status, body = http(f"http://127.0.0.1:{port}/healthz")
                    if status == 200:
                        break
                except OSError:
                    if time.time() > deadline:
                        raise
                    time.sleep(0.1)

            # The process is really listening on all interfaces...
            with socket.create_connection((address, port), timeout=5):
                pass
            # ...yet every request from the non-loopback address is rejected.
            base = f"http://{address}:{port}"
            for path in ("/healthz", "/openapi.json", "/v1/state/genesis"):
                status, body = http(base + path)
                assert status == 403 and body == REJECTION, (path, status, body)

            with sqlite3.connect(db_path) as conn:
                before = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            status, body = http(
                base + "/v1/evidence",
                "POST",
                {
                    "requester_identity_id": "identity:nathan",
                    "authority_grant_id": "grant:genesis-root",
                    "payload": {"probe": "api-0-loopback"},
                },
            )
            assert status == 403 and body == REJECTION, (status, body)
            with sqlite3.connect(db_path) as conn:
                after = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            assert after == before, "non-loopback write reached the Kernel"

            # Loopback clients of the very same uvicorn process are unaffected.
            status, body = http(f"http://127.0.0.1:{port}/v1/state/genesis")
            assert status == 200 and body["state_id"] == "state:genesis", (status, body)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return f"uvicorn api_server:app --host 0.0.0.0 probed from {address}: 403 on reads and write, Kernel untouched"


def main() -> None:
    check_startup_refusal()
    check_asgi_boundary()
    live = check_uvicorn_bypass_is_closed()

    print("api_0_6_loopback_launch_contract: OK")
    print("  python api_server.py with API_HOST=0.0.0.0: refused at startup (non-zero exit)")
    print("  ASGI boundary: loopback peers served; 9 non-loopback/malformed peers x 5 routes rejected (403)")
    print(f"  {live}")


if __name__ == "__main__":
    main()
