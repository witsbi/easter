"""GATEWAY-1: dual opaque/Ed25519 authentication during migration overlap.

Exercises the signed-token path against a real gateway app, MCP subprocess,
and scratch kernel while preserving the opaque SessionStore path. The broker's
issuance database is a separate scratch database and the gateway opens it only
through the read-only IssuanceReader.

Checks:
  ET-1  Existing opaque tokens still authenticate unchanged.
  ET-2  Signed reader and agent tokens authenticate and identity binding holds.
  ET-3  Unknown, revoked, expired, tampered, malformed, and bad-role tokens fail.
  ET-4  Rotation overlap keeps old tokens valid while new mints use the new key.
  ET-5  Issuance database outages fail closed without creating/replacing the DB.
  ET-6  A revoked kernel grant fires the signed-token trip-wire in-process.
  ET-7  Gateway keeps its structural no-direct-SQLite/kernel boundary.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn

import gateway
from broker import tokens
from broker.issuance import Issuance, new_jti
from broker.reader import IssuanceReadError, IssuanceReader
from gateway import MCPBackend, SessionStore, make_app
from initialize import initialize_database
from kernel import Kernel

ROOT = "identity:root"
WORKER = "identity:enterprise-worker"
INTRUDER = "identity:enterprise-intruder"
ROOT_GRANT = "grant:genesis-root"
AUTHORITY = "authority:enterprise-scope"


def check(label: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))
    if not condition:
        check.failed = True


check.failed = False


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="gateway-enterprise-"))
    kernel_db = tmp / "kernel.db"
    sessions_path = tmp / "sessions.json"
    issuance_db = tmp / "issuance.db"
    key_dir = tmp / "keys"

    initialize_database(kernel_db, ROOT)
    kernel = Kernel(str(kernel_db))
    kernel.transition(
        requester_identity_id=ROOT,
        from_state_id="state:genesis",
        authority_grant_id=ROOT_GRANT,
        new_state_payload={"gateway": "enterprise-bootstrap"},
        transition_payload={"reason": "GATEWAY-1 setup"},
        new_identities=[
            {"identity_id": WORKER, "payload": {"role": "agent"}},
            {"identity_id": INTRUDER, "payload": {"role": "intruder"}},
        ],
    )
    kernel.define_authority(
        requester_identity_id=ROOT,
        authority_grant_id=ROOT_GRANT,
        authority_id=AUTHORITY,
        payload={"scope": "gateway-enterprise"},
    )
    grant = kernel.grant(
        requester_identity_id=ROOT,
        authority_grant_id=ROOT_GRANT,
        identity_id=WORKER,
        authority_id=AUTHORITY,
        payload={"test": "gateway-enterprise"},
    )
    worker_grant = grant["grant_id"]

    issuance = Issuance(issuance_db, key_dir)

    # This test is about gateway verification, not OS keychain integration
    # (covered by broker_1). Keep test keys entirely inside the scratch dir.
    def store_test_key(key_id: str, raw: bytes) -> str:
        path = key_dir / f"{key_id}.key"
        path.write_bytes(raw)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return f"file:{path}"

    issuance._store_private_key = store_test_key  # type: ignore[method-assign]
    key_1 = issuance.generate_key(actor=ROOT)

    def issue(
        *,
        identity: str = WORKER,
        grants: list[str] | None = None,
        role: str = "reader",
        ttl: timedelta = timedelta(minutes=10),
        key_id: str | None = None,
        record: bool = True,
    ) -> tuple[str, str]:
        selected_key = key_id or issuance.active_key()["id"]  # type: ignore[index]
        jti = new_jti()
        token, claims = tokens.mint(
            private_key=issuance.get_private_key(selected_key),
            key_id=selected_key,
            identity=identity,
            grants=list(grants or []),
            jti=jti,
            role=role,
            ttl=ttl,
        )
        if record:
            issuance.record_token(
                jti=jti,
                identity=claims.sub,
                grants_json=json.dumps(claims.grants),
                key_id=selected_key,
                issued_at=claims.iat,
                expires_at=claims.exp,
                label=claims.lbl,
                actor=ROOT,
            )
        return token, jti

    signed_reader, _ = issue(role="reader")
    signed_agent, signed_agent_jti = issue(
        role="agent", grants=[worker_grant]
    )
    signed_expired, _ = issue(role="reader", ttl=timedelta(seconds=-1))
    signed_unknown, _ = issue(role="reader", record=False)
    signed_bad_role, _ = issue(role="super-admin")

    store = SessionStore(sessions_path)
    opaque_reader = store.mint(
        identity_id=WORKER,
        grant_ids=[worker_grant],
        role="reader",
        ttl_seconds=600,
        label="enterprise-overlap",
    )

    reader = IssuanceReader(issuance_db)
    missing_db = tmp / "must-not-be-created.db"
    try:
        IssuanceReader(missing_db).resolve_public_key("key:none")
        check("ET-5a: missing issuance DB fails closed", False)
    except IssuanceReadError:
        check("ET-5a: missing issuance DB fails closed", not missing_db.exists())

    backend = MCPBackend(str(kernel_db))
    app = make_app(store, backend, reader)
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    def request(token: str, tool: str, body: dict) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request(
            "POST",
            f"/tools/{tool}",
            body=json.dumps(body),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = conn.getresponse()
        raw = response.read().decode()
        conn.close()
        try:
            return response.status, json.loads(raw)
        except json.JSONDecodeError:
            return response.status, {"_raw": raw}

    def wait_ready() -> None:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                conn.request("GET", "/health")
                response = conn.getresponse()
                response.read()
                conn.close()
                if response.status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("gateway did not start")

    try:
        wait_ready()

        status, _ = request(
            opaque_reader, "get_state", {"state_id": "state:genesis"}
        )
        check("ET-1: opaque migration-overlap token still works", status == 200)

        status, _ = request(
            signed_reader, "get_state", {"state_id": "state:genesis"}
        )
        check("ET-2a: signed reader token works", status == 200, f"status={status}")

        status, body = request(
            signed_agent,
            "transition",
            {
                "requester_identity_id": INTRUDER,
                "from_state_id": "state:genesis",
                "authority_grant_id": worker_grant,
                "new_state_payload": {"signed": True},
            },
        )
        check(
            "ET-2b: signed agent transition succeeds with bound identity",
            status == 200,
            f"status={status} body={str(body)[:120]}",
        )

        for label, bad_token in [
            ("unknown jti", signed_unknown),
            ("expired", signed_expired),
            ("malformed", "W10.e30.AA"),
            ("bad role", signed_bad_role),
        ]:
            status, _ = request(
                bad_token, "get_state", {"state_id": "state:genesis"}
            )
            check(f"ET-3: {label} token rejected", status == 403, f"status={status}")

        parts = signed_reader.split(".")
        tampered_payload = json.loads(tokens._b64url_decode(parts[1]))
        tampered_payload["sub"] = INTRUDER
        parts[1] = tokens._b64url_encode(
            json.dumps(tampered_payload, separators=(",", ":")).encode()
        )
        status, _ = request(
            ".".join(parts), "get_state", {"state_id": "state:genesis"}
        )
        check("ET-3: tampered signed token rejected", status == 403, f"status={status}")

        revoked_token, revoked_jti = issue(role="reader")
        issuance.revoke_token(revoked_jti, actor=ROOT)
        status, _ = request(
            revoked_token, "get_state", {"state_id": "state:genesis"}
        )
        check("ET-3: broker-denylisted token rejected", status == 403)

        # Rotate after the server is already running. Reader lookups are live,
        # so the old key remains usable during overlap and the new key is seen.
        key_2 = issuance.generate_key(actor=ROOT)
        issuance.retire_key(key_1["key_id"], actor=ROOT)
        new_reader, _ = issue(role="reader", key_id=key_2["key_id"])
        old_status, _ = request(
            signed_reader, "get_state", {"state_id": "state:genesis"}
        )
        new_status, _ = request(
            new_reader, "get_state", {"state_id": "state:genesis"}
        )
        check(
            "ET-4: key-rotation overlap accepts old and new tokens",
            old_status == 200 and new_status == 200,
            f"old={old_status} new={new_status}",
        )

        # Move the issuance DB away. Signed auth must fail closed and must not
        # recreate the database; opaque auth must remain independent.
        parked_db = tmp / "issuance.parked"
        issuance_db.replace(parked_db)
        signed_status, _ = request(
            new_reader, "get_state", {"state_id": "state:genesis"}
        )
        opaque_status, _ = request(
            opaque_reader, "get_state", {"state_id": "state:genesis"}
        )
        check(
            "ET-5b: issuance outage rejects signed token without recreating DB",
            signed_status == 403 and not issuance_db.exists(),
            f"status={signed_status}",
        )
        check(
            "ET-5c: issuance outage does not break opaque path",
            opaque_status == 200,
            f"status={opaque_status}",
        )
        parked_db.replace(issuance_db)

        # The kernel keeps revocation bookkeeping. The first signed-token
        # write reaches the kernel and fires the trip-wire; later attempts are
        # rejected before another receipt can be produced.
        before = len(kernel.list_records(record_type="receipt", limit=1000)["items"])
        kernel.revoke(
            requester_identity_id=ROOT,
            authority_grant_id=ROOT_GRANT,
            grant_id=worker_grant,
            reason="GATEWAY-1 trip-wire",
        )
        first_status, _ = request(
            signed_agent,
            "transition",
            {
                "from_state_id": "state:genesis",
                "authority_grant_id": worker_grant,
                "new_state_payload": {"must": "fail"},
            },
        )
        after_first = len(
            kernel.list_records(record_type="receipt", limit=1000)["items"]
        )
        second_status, _ = request(
            signed_agent,
            "transition",
            {
                "from_state_id": "state:genesis",
                "authority_grant_id": worker_grant,
                "new_state_payload": {"must": "still-fail"},
            },
        )
        after_second = len(
            kernel.list_records(record_type="receipt", limit=1000)["items"]
        )
        check(
            "ET-6a: revoked grant fires signed-token trip-wire",
            first_status == 403 and after_first == before + 2,
            f"status={first_status} receipts={before}->{after_first}",
        )
        check(
            "ET-6b: later signed-token attempt is blocked without new receipt",
            second_status == 403 and after_second == after_first,
            f"status={second_status} receipts={after_first}->{after_second}",
        )

        source = Path(gateway.__file__).read_text()
        check("ET-7a: gateway still never imports kernel", "import kernel" not in source and "from kernel" not in source)
        check("ET-7b: gateway still never imports sqlite3", "sqlite3" not in source)
        check("ET-7c: signed-token reader is configured by CLI", gateway._build_parser().parse_args(["serve", "--cert", "c", "--key", "k", "--issuance-db", str(issuance_db)]).issuance_db == str(issuance_db))

    finally:
        server.should_exit = True
        thread.join(timeout=10)
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nGATEWAY-1 complete: " + ("ALL PASS" if not check.failed else "FAILURES PRESENT"))
    raise SystemExit(1 if check.failed else 0)


if __name__ == "__main__":
    main()
