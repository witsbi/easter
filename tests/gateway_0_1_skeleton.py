"""
GATEWAY-0-1 -- Gateway skeleton: authenticate, bind, forward.

Exercises the EASTER-GATEWAY-0 skeleton end to end against a scratch
database:

  GW-1  Valid token -> transition succeeds through the gateway.
  GW-2  Smuggled requester_identity_id -> overwritten with the session
        identity (the operation is attributed to the session, and a
        foreign identity's (lack of) grants cannot be borrowed).
  GW-2b Direct durable assertion: the committed transition record
        carries the session's grant, whose holder is the session
        identity -- not the smuggled one.
  GW-3  Foreign authority_grant_id -> 403 at the gateway, kernel
        untouched (no receipt-spam: receipt count does not move).
  GW-4  Admin tool (grant) -> 403. Admin tools exist in no gateway role.
  GW-5  Bad token and expired token -> 403, kernel untouched.
  GW-6  Structural: gateway.py never imports kernel.py / sqlite3 and
        never opens the kernel database itself (same technique as
        api_0_3_no_direct_kernel_access.py).
  GW-7  Revoked grant + live token -> 403 trip-wire: the session is
        killed server-side and kernel spam is bounded to exactly one
        rejected receipt; later attempts 403 at the gateway.
  GW-7b Born-expired grant + live token -> 403 at the gateway's
        liveness pre-check: zero receipts, session revoked.
  GW-8  Reader role: reads work (shared-read invariant is documented,
        not enforced), writes -> 403.
  GW-9  Unknown tool -> 403.
  GW-13 Grant/identity enumeration is self-scoped with no bypass:
        list_records refuses the grant/identity record types, get_grant
        serves only the session's own grant set, other record types
        stay shared-world.
  GW-14 get_identity/list_grants_for_identity inject the session
        identity when the argument is absent and overwrite it when
        smuggled: always self-scoped, never a 502 on a missing arg.
  GW-10 TTL is capped at MAX_TTL_SECONDS; non-positive ttl is refused.
        serve defaults to loopback.
  GW-11 Corrupt session file fails closed (403, never 500) and the
        gateway recovers when the file is restored.
  GW-12 revoke-token accepts the unambiguous prefix shown by list;
        ambiguous prefixes are refused.

Run:  cd ~/workspace/easter && /tmp/gw-venv/bin/python tests/gateway_0_1_skeleton.py
"""

import datetime as dt
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from initialize import initialize_database
from kernel import Kernel

import gateway
from gateway import SessionStore, make_app, MCPBackend, _token_hash, _build_parser

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
    tmp = Path(tempfile.mkdtemp(prefix="gw0_"))
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
    counter_token = store.mint(
        identity_id=WORKER, grant_ids=[WORKER_GRANT], role="reader",
        ttl_seconds=600, label="gw-0-1-counter",
    )
    # An expired session, built deterministically: mint live, backdate.
    dead_token = store.mint(
        identity_id=WORKER, grant_ids=[WORKER_GRANT], role="agent",
        ttl_seconds=600, label="gw-0-1-expired",
    )
    data = store._load()
    data[_token_hash(dead_token)]["expires_at"] = "2000-01-01T00:00:00Z"
    store._save(data)
    assert store.lookup(dead_token) is None, "backdated token must read as expired"

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
        st, body = post("list_records", counter_token, {"record_type": "receipt", "limit": 1000})
        assert st == 200, f"list_records failed: {body}"
        return len(body["result"]["items"])

    def transition_body(from_state, **kw):
        b = {
            "from_state_id": from_state,
            "authority_grant_id": WORKER_GRANT,
            "new_state_payload": {"gw": "0-1"},
        }
        b.update(kw)
        return b

    try:
        wait_ready()

        # --- GW-1: valid token, transition through the gateway ---
        st, body = post("transition", agent_token, transition_body(
            "state:genesis",
            requester_identity_id=WORKER,  # will be (re)bound anyway
            new_state_payload={"gw": "0-1", "n": 1},
            transition_payload={"reason": "GW-1"},
        ))
        check("GW-1: valid token transition succeeds", st == 200, f"status={st} {str(body)[:100]}")
        s1 = body["result"]["state_id"] if st == 200 else None

        # --- GW-2: smuggled identity is overwritten ---
        st2, body2 = post("transition", agent_token, transition_body(
            s1,
            requester_identity_id=INTRUDER,  # smuggle attempt
            new_state_payload={"gw": "0-1", "n": 2},
            transition_payload={"reason": "GW-2 smuggle"},
        ))
        # If the smuggle had worked, the kernel would reject: intruder
        # holds no grants ("does not hold grant"). Success proves the
        # gateway overwrote the identity with the session's.
        ok2 = st2 == 200
        check("GW-2: smuggled requester_identity_id is overwritten", ok2,
              f"status={st2} {str(body2)[:100]}")
        s2 = body2["result"]["state_id"] if ok2 else s1

        # --- GW-2b: direct durable assertion on the committed record ---
        if ok2:
            tid = body2["result"]["transition_id"]
            _, tr = post("get_transition", agent_token, {"transition_id": tid})
            tgrant = tr["result"]["authority_grant_id"]
            _, gr = post("get_grant", agent_token, {"grant_id": tgrant})
            check("GW-2b: transition record carries the session grant",
                  tgrant == WORKER_GRANT, f"grant={tgrant}")
            check("GW-2b: session grant is held by the session identity, not the intruder",
                  gr["result"]["identity_id"] == WORKER, f"holder={gr['result']['identity_id']}")

        # --- GW-3: foreign grant id -> 403, kernel untouched ---
        before = receipt_count()
        st3, body3 = post("transition", agent_token, transition_body(
            s2,
            requester_identity_id=WORKER,
            authority_grant_id=ROOT_GRANT,  # not in session set
            new_state_payload={"gw": "0-1", "evil": True},
        ))
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
        st5a, _ = post("transition", "bogus-token", {"from_state_id": s2})
        check("GW-5a: bogus token rejected", st5a == 403, f"status={st5a}")
        st5b, _ = post("transition", dead_token, {"from_state_id": s2})
        check("GW-5b: expired token rejected", st5b == 403, f"status={st5b}")
        st5c, _ = post("transition", None, {"from_state_id": s2})
        check("GW-5c: missing token rejected", st5c == 401, f"status={st5c}")
        check("GW-5: no receipt-spam from bad tokens", receipt_count() == before)

        # --- GW-8: reader role ---
        reader_token = store.mint(
            identity_id=WORKER, grant_ids=[WORKER_GRANT], role="reader",
            ttl_seconds=600, label="gw-0-1-reader",
        )
        st8a, _ = post("list_records", reader_token, {"record_type": "receipt", "limit": 1})
        check("GW-8a: reader role can read (shared-read invariant is documented)",
              st8a == 200, f"status={st8a}")
        st8b, _ = post("transition", reader_token, transition_body(s2))
        check("GW-8b: reader role cannot write", st8b == 403, f"status={st8b}")

        # --- GW-9: unknown tool ---
        st9, _ = post("no_such_tool", agent_token, {})
        check("GW-9: unknown tool denied", st9 == 403, f"status={st9}")

        # --- GW-13: grant/identity enumeration is self-scoped, no bypass ---
        st13a, _ = post("list_records", agent_token, {"record_type": "grant", "limit": 5})
        check("GW-13a: list_records cannot enumerate grants", st13a == 403,
              f"status={st13a}")
        st13b, _ = post("list_records", agent_token, {"record_type": "identity", "limit": 5})
        check("GW-13b: list_records cannot enumerate identities", st13b == 403,
              f"status={st13b}")
        st13c, _ = post("get_grant", agent_token, {"grant_id": ROOT_GRANT})
        check("GW-13c: get_grant refused outside the session grant set",
              st13c == 403, f"status={st13c}")
        st13d, bg13d = post("get_grant", agent_token, {"grant_id": WORKER_GRANT})
        check("GW-13d: get_grant serves the session's own grants",
              st13d == 200 and bg13d["result"]["grant_id"] == WORKER_GRANT,
              f"status={st13d}")
        st13e, _ = post("list_records", agent_token, {"record_type": "receipt", "limit": 5})
        check("GW-13e: other record types stay shared-world", st13e == 200,
              f"status={st13e}")

        # --- GW-14: self-scoped identity tools inject the session identity ---
        # Regression: get_identity/list_grants_for_identity with no
        # identity_id argument used to forward the call unbound, and the
        # MCP server rejected the missing required argument (502). The
        # session identity is now injected when absent, overwritten when
        # smuggled -- the tool is always self-scoped.
        st14a, bg14a = post("get_identity", agent_token, {})
        check("GW-14a: get_identity with no args returns the session identity",
              st14a == 200 and bg14a["result"]["identity_id"] == WORKER,
              f"status={st14a} {str(bg14a)[:100]}")
        st14b, bg14b = post("get_identity", agent_token, {"identity_id": INTRUDER})
        check("GW-14b: smuggled identity_id is overwritten with the session identity",
              st14b == 200 and bg14b["result"]["identity_id"] == WORKER,
              f"status={st14b} {str(bg14b)[:100]}")
        st14c, bg14c = post("list_grants_for_identity", agent_token, {})
        got14c = st14c == 200 and all(
            g["identity_id"] == WORKER for g in bg14c["result"]["items"]
        )
        check("GW-14c: list_grants_for_identity with no args is self-scoped",
              got14c, f"status={st14c} {str(bg14c)[:100]}")

        # --- GW-10: TTL bounds and loopback default ---
        big = store.mint(
            identity_id=WORKER, grant_ids=[WORKER_GRANT], role="agent",
            ttl_seconds=10 ** 9, label="gw-huge-ttl",
        )
        exp = gateway._parse_ts(store._load()[_token_hash(big)]["expires_at"])
        remaining = (exp - dt.datetime.now(dt.timezone.utc)).total_seconds()
        check("GW-10a: ttl capped at MAX_TTL_SECONDS",
              remaining <= gateway.MAX_TTL_SECONDS + 5, f"remaining={remaining:.0f}s")
        refused = 0
        for bad in (0, -30):
            try:
                store.mint(identity_id=WORKER, grant_ids=[WORKER_GRANT],
                           role="agent", ttl_seconds=bad)
            except ValueError:
                refused += 1
        check("GW-10b: non-positive ttl refused", refused == 2)
        serve_args = _build_parser().parse_args(
            ["serve", "--cert", "c", "--key", "k"])
        check("GW-10c: serve defaults to loopback",
              serve_args.host == "127.0.0.1", f"host={serve_args.host}")

        # --- GW-12: revoke by prefix ---
        gw12_token = store.mint(
            identity_id=WORKER, grant_ids=[WORKER_GRANT], role="agent",
            ttl_seconds=600, label="gw12",
        )
        prefix = next(e["token_prefix"] for e in store.list_sessions()
                      if e["label"] == "gw12")
        try:
            store.revoke("")
            check("GW-12a: ambiguous prefix refused", False, "empty prefix matched one")
        except ValueError:
            check("GW-12a: ambiguous prefix refused", True)
        check("GW-12b: revoke by unambiguous prefix works",
              store.revoke(prefix) is True)
        check("GW-12c: revoked-by-prefix token is dead",
              store.lookup(gw12_token) is None)

        # --- GW-11: corrupt session file fails closed ---
        raw_sessions = sessions.read_bytes()
        sessions.write_bytes(b"{corrupt")
        st11, _ = post("transition", agent_token, transition_body(s2))
        check("GW-11a: corrupt session file -> 403, never 500", st11 == 403, f"status={st11}")
        sessions.write_bytes(raw_sessions)
        st11b, _ = post("get_state", agent_token, {"state_id": "state:genesis"})
        check("GW-11b: gateway recovers when the file is restored", st11b == 200,
              f"status={st11b}")

        # --- GW-7: revoked grant + live token -> trip-wire ---
        kernel.revoke(
            requester_identity_id=ROOT,
            authority_grant_id=ROOT_GRANT,
            grant_id=WORKER_GRANT,
        )
        before7 = receipt_count()
        st7, body7 = post("transition", agent_token, transition_body(s2))
        check("GW-7a: revoked grant -> 403", st7 == 403, f"status={st7} {str(body7)[:80]}")
        check("GW-7b: trip-wire bounds kernel spam to exactly one receipt",
              receipt_count() == before7 + 1, f"before={before7}")
        st7c, _ = post("transition", agent_token, transition_body(s2))
        check("GW-7c: session killed after trip-wire (later attempts 403 at gateway)",
              st7c == 403, f"status={st7c}")
        check("GW-7d: no further receipts after the kill",
              receipt_count() == before7 + 1)

        # --- GW-7b: born-expired grant + live token -> pre-check, zero receipts ---
        eg = kernel.grant(
            requester_identity_id=ROOT,
            authority_grant_id=ROOT_GRANT,
            identity_id=WORKER,
            authority_id=AUTH,
            valid_from="1999-01-01T00:00:00Z",
            expires_at="2000-01-01T00:00:00Z",
            payload={"gw": "expired-grant"},
        )
        exp_token = store.mint(
            identity_id=WORKER, grant_ids=[eg["grant_id"]], role="agent",
            ttl_seconds=600, label="gw-expired-grant",
        )
        before7b = receipt_count()
        st7e, _ = post("transition", exp_token, {
            "from_state_id": s2,
            "authority_grant_id": eg["grant_id"],
            "new_state_payload": {"gw": "0-1"},
        })
        check("GW-7e: expired grant -> 403 at the gateway", st7e == 403, f"status={st7e}")
        check("GW-7f: zero kernel receipts for the expired grant (liveness pre-check)",
              receipt_count() == before7b, f"before={before7b}")

        # --- GW-6: structural no-direct-kernel-access ---
        src = Path(gateway.__file__).read_text()
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
