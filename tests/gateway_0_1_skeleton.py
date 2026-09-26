"""
GATEWAY-0-1 -- Gateway skeleton: authenticate, bind, forward.

Exercises the EASTER-GATEWAY-0 skeleton end to end against a scratch
database:

  GW-1  Valid token -> transition succeeds through the gateway.
  GW-2  Smuggled requester_identity_id -> overwritten with the session
        identity (the operation is attributed to the session, and a
        foreign identity's (lack of) grants cannot be borrowed).
  GW-3  Foreign authority_grant_id -> 403 at the gateway, kernel
        untouched (no receipt-spam: receipt count does not move).
  GW-4  Admin tool (grant) -> 403. Admin tools exist in no gateway role.
  GW-5  Bad token and expired token -> 403, kernel untouched.
  GW-6  Structural: gateway.py never imports kernel.py / sqlite3 and
        never opens the kernel database itself (same technique as
        api_0_3_no_direct_kernel_access.py).

Run:  cd ~/workspace/easter && /tmp/gw-venv/bin/python tests/gateway_0_1_skeleton.py
"""

import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, "/home/hatch/workspace/easter")

from initialize import initialize_database
from kernel import Kernel

import gateway
from gateway import SessionStore, make_app, MCPBackend

PORT = 18443
ROOT = "identity:root"
WORKER = "identity:worker"
INTRUDER = "identity:intruder"
ROOT_GRANT = "grant:genesis-root"
AUTH = "authority:gw-scope"


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))
    if not cond:
        check.failed = True


check.failed = False


def main():
    tmp = Path = __import__("pathlib").Path(tempfile.mkdtemp(prefix="gw0_"))
    db = tmp / "kernel.db"
    sessions = tmp / "sessions.json"
    cert = tmp / "cert.pem"
    key = tmp / "key.pem"

    # --- world setup through the kernel boundary ---
    initialize_database(db, ROOT)
    kernel = Kernel(str(db))
    kernel.transition(
        requester_identity_id=ROOT,
        from_state_id="state:genesis",
        authority_grant_id=ROOT_GRANT,
        new_state_payload={"gw": "bootstrap"},
        transition_payload={"reason": "GW-0-1 setup"},
        new_identities=[
            {"identity_id": WORKER, "payload": {"role": "agent"}},
            {"identity_id": INTRUDER, "payload": {"role": "intruder"}},
        ],
    )
    kernel.define_authority(
        requester_identity_id=ROOT,
        authority_grant_id=ROOT_GRANT,
        authority_id=AUTH,
        payload={"scope": "gw-0-1"},
    )
    g = kernel.grant(
        requester_identity_id=ROOT,
        authority_grant_id=ROOT_GRANT,
        identity_id=WORKER,
        authority_id=AUTH,
        payload={"gw": "0-1"},
    )
    WORKER_GRANT = g["grant_id"]

    # --- mint tokens (the local ceremony) ---
    store = SessionStore(sessions)
    agent_token = store.mint(
        identity_id=WORKER, grant_ids=[WORKER_GRANT], role="agent",
        ttl_seconds=600, label="gw-0-1-agent",
    )
    dead_token = store.mint(
        identity_id=WORKER, grant_ids=[WORKER_GRANT], role="agent",
        ttl_seconds=0, label="gw-0-1-expired",
    )
    assert store.lookup(dead_token) is None, "ttl=0 token must read as expired"

    # --- self-signed cert for the test listener ---
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )

    # --- start the gateway ---
    import uvicorn

    backend = MCPBackend(str(db))
    app = make_app(store, backend)
    config = uvicorn.Config(
        app, host="127.0.0.1", port=PORT,
        ssl_certfile=str(cert), ssl_keyfile=str(key),
        log_level="error",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    ctx = ssl.create_default_context(cafile=str(cert))
    ctx.check_hostname = False  # test pins the cert file itself

    def wait_ready():
        for _ in range(100):
            try:
                conn = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=2)
                conn.request("GET", "/health")
                resp = conn.getresponse()
                if resp.status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("gateway did not start")

    def post(tool, token, body):
        conn = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=10)
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        conn.request("POST", f"/tools/{tool}", body=json.dumps(body), headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode()
        try:
            return resp.status, json.loads(raw)
        except json.JSONDecodeError:
            return resp.status, {"_raw": raw}

    def receipt_count():
        st, body = post("list_records", agent_token, {"record_type": "receipt", "limit": 1000})
        assert st == 200, f"list_records failed: {body}"
        return len(body["result"]["items"])

    try:
        wait_ready()

        # --- GW-1: valid token, transition through the gateway ---
        st, body = post("transition", agent_token, {
            "requester_identity_id": WORKER,  # will be (re)bound anyway
            "from_state_id": "state:genesis",
            "authority_grant_id": WORKER_GRANT,
            "new_state_payload": {"gw": "0-1", "n": 1},
            "transition_payload": {"reason": "GW-1"},
        })
        check("GW-1: valid token transition succeeds", st == 200, f"status={st} {str(body)[:100]}")
        s1 = body["result"]["state_id"] if st == 200 else None

        # --- GW-2: smuggled identity is overwritten ---
        st2, body2 = post("transition", agent_token, {
            "requester_identity_id": INTRUDER,  # smuggle attempt
            "from_state_id": s1,
            "authority_grant_id": WORKER_GRANT,
            "new_state_payload": {"gw": "0-1", "n": 2},
            "transition_payload": {"reason": "GW-2 smuggle"},
        })
        # If the smuggle had worked, the kernel would reject: intruder
        # holds no grants ("does not hold grant"). Success proves the
        # gateway overwrote the identity with the session's.
        ok2 = st2 == 200
        check("GW-2: smuggled requester_identity_id is overwritten", ok2,
              f"status={st2} {str(body2)[:100]}")
        if ok2:
            stl, bl = post("list_transitions_by_grant", agent_token,
                           {"authority_grant_id": WORKER_GRANT})
            ids = [t["transition_id"] for t in bl["result"]["items"]]
            check("GW-2: smuggled op attributed to session grant",
                  body2["result"]["transition_id"] in ids)

        # --- GW-3: foreign grant id -> 403, kernel untouched ---
        before = receipt_count()
        st3, body3 = post("transition", agent_token, {
            "requester_identity_id": WORKER,
            "from_state_id": s1,
            "authority_grant_id": ROOT_GRANT,  # not in session set
            "new_state_payload": {"gw": "0-1", "evil": True},
        })
        check("GW-3: foreign authority_grant_id rejected", st3 == 403, f"status={st3}")
        check("GW-3: no receipt-spam (receipt count unchanged)",
              receipt_count() == before, f"before={before}")

        # --- GW-4: admin tool unreachable ---
        st4, body4 = post("grant", agent_token, {
            "requester_identity_id": WORKER,
            "authority_grant_id": WORKER_GRANT,
            "identity_id": INTRUDER,
            "authority_id": AUTH,
        })
        check("GW-4: admin tool 'grant' unreachable via gateway", st4 == 403, f"status={st4}")

        # --- GW-5: bad and expired tokens ---
        st5a, _ = post("transition", "bogus-token", {"from_state_id": s1})
        check("GW-5a: bogus token rejected", st5a == 403, f"status={st5a}")
        st5b, _ = post("transition", dead_token, {"from_state_id": s1})
        check("GW-5b: expired token rejected", st5b == 403, f"status={st5b}")
        st5c, _ = post("transition", None, {"from_state_id": s1})
        check("GW-5c: missing token rejected", st5c == 401, f"status={st5c}")
        check("GW-5: no receipt-spam from bad tokens", receipt_count() == before)

        # --- GW-6: structural no-direct-kernel-access ---
        src = (__import__("pathlib").Path(gateway.__file__)).read_text()
        check("GW-6a: gateway.py never imports kernel",
              "import kernel" not in src and "from kernel" not in src)
        check("GW-6b: gateway.py never imports sqlite3", "sqlite3" not in src)
        check("GW-6c: gateway.py never names the kernel db file",
              "kernel.db" not in src)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nGW-0-1 complete: " + ("ALL PASS" if not check.failed else "FAILURES PRESENT"))
    sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
    main()
