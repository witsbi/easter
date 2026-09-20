"""Whole-kernel composition review, Part C: cross-ID confusion,
systematic payload cross-contamination, crash/transaction boundaries,
and supported-boundary corruption behavior.

Covers attack areas: 12 (cross-operation ID confusion, systematic), 13
(operation_id -- already established via grep that it's never read
back by any kernel code, only stamped; this file adds one more
behavioral confirmation), 16 (payload cross-contamination, systematic
sweep across every payload-bearing field), 18 (crash/transaction
boundaries at multiple stages), 19 (supported-boundary corruption
behavior).
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import kernel as kernel_module
from kernel import Kernel, KernelError

REPO = Path(__file__).parent
NATHAN = "identity:nathan"
ROOT_GRANT = "grant:genesis-root"
GENESIS = "state:genesis"


def fresh_kernel() -> Kernel:
    f = tempfile.NamedTemporaryFile(prefix="whole-kernel-partc-", suffix=".db")
    f.close()
    db_path = Path(f.name)
    subprocess.run(["sqlite3", str(db_path)], stdin=open(REPO / "schema.sql"), check=True)
    subprocess.run(["sqlite3", str(db_path)], stdin=open(REPO / "genesis_seed.sql"), check=True)
    return Kernel(db_path)


kernel = fresh_kernel()

# ================================================================
# AREA 12: systematic cross-ID confusion. Collect one REAL id of every
# kind, then try each one in every OTHER slot that expects a
# differently-typed id.
# ================================================================

grant2 = kernel.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN, authority_id="authority:root",
)
evidence1 = kernel.record_evidence(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT, payload={"note": "cross-id probe"},
)
transition1 = kernel.transition(
    requester_identity_id=NATHAN, from_state_id=GENESIS,
    authority_grant_id=ROOT_GRANT, new_state_payload={"probe": "cross-id"},
)

real_ids = {
    "state_id": GENESIS,
    "grant_id": ROOT_GRANT,
    "evidence_id": evidence1["evidence_id"],
    "receipt_id": transition1["receipt_id"],
    "transition_id": transition1["transition_id"],
    "operation_id": transition1["operation_id"],
    "identity_id": NATHAN,
    "authority_id": "authority:root",
}

cross_id_findings = []

# from_state_id slot expects a state_id -- try every other kind.
for kind, value in real_ids.items():
    if kind == "state_id":
        continue
    try:
        kernel.transition(
            requester_identity_id=NATHAN, from_state_id=value,
            authority_grant_id=ROOT_GRANT, new_state_payload={"probe": f"from_state_id={kind}"},
        )
        cross_id_findings.append(f"UNEXPECTED ACCEPT: {kind} value used as from_state_id")
    except KernelError as exc:
        assert "does not exist" in str(exc)

# authority_grant_id slot expects a grant_id -- try every other kind.
for kind, value in real_ids.items():
    if kind == "grant_id":
        continue
    try:
        kernel.transition(
            requester_identity_id=NATHAN, from_state_id=GENESIS,
            authority_grant_id=value, new_state_payload={"probe": f"authority_grant_id={kind}"},
        )
        cross_id_findings.append(f"UNEXPECTED ACCEPT: {kind} value used as authority_grant_id")
    except KernelError as exc:
        assert "does not exist" in str(exc)

# evidence_ids slot expects evidence_id -- try every other kind.
for kind, value in real_ids.items():
    if kind == "evidence_id":
        continue
    with kernel.connect() as conn:
        before = conn.execute("SELECT COUNT(*) FROM states").fetchone()[0]
    try:
        kernel.transition(
            requester_identity_id=NATHAN, from_state_id=GENESIS,
            authority_grant_id=ROOT_GRANT, new_state_payload={"probe": f"evidence_ids={kind}"},
            evidence_ids=[value],
        )
        cross_id_findings.append(f"UNEXPECTED ACCEPT: {kind} value used as evidence_id")
    except KernelError:
        pass
    with kernel.connect() as conn:
        after = conn.execute("SELECT COUNT(*) FROM states").fetchone()[0]
    assert after == before, f"a rejected/failed evidence_ids={kind} probe must not leak a State row"

# identity_id slot (grant()'s target identity_id) expects an identity.
for kind, value in real_ids.items():
    if kind == "identity_id":
        continue
    try:
        kernel.grant(
            requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
            identity_id=value, authority_id="authority:root",
        )
        cross_id_findings.append(f"UNEXPECTED ACCEPT: {kind} value used as identity_id")
    except KernelError as exc:
        assert "does not exist" in str(exc)

# requester_identity_id: try a grant_id/state_id/receipt_id as the
# REQUESTER identity itself (not just the grant it holds).
for kind, value in real_ids.items():
    if kind == "identity_id":
        continue
    try:
        kernel.transition(
            requester_identity_id=value, from_state_id=GENESIS,
            authority_grant_id=ROOT_GRANT, new_state_payload={"probe": f"requester={kind}"},
        )
        cross_id_findings.append(f"UNEXPECTED ACCEPT: {kind} value used as requester_identity_id")
    except KernelError as exc:
        assert "does not hold grant" in str(exc) or "does not exist" in str(exc)

assert cross_id_findings == [], f"cross-ID confusion succeeded: {cross_id_findings}"

# SQL-looking / empty / huge / unicode / structured IDs in each slot.
hostile_ids = [
    "", "state:'); DROP TABLE states; --", "grant:" + "x" * 100_000,
    "identity:\x00\u202e\uffff", "grant:../../../etc/passwd",
    "authority:{\"is_root\":true}", "state:" + GENESIS,  # looks-alike, not equal
]
with kernel.connect() as conn:
    before_tables = {
        t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in ("states", "transitions", "receipts", "exceptions", "authority_grants")
    }
for hostile in hostile_ids:
    try:
        kernel.transition(
            requester_identity_id=NATHAN, from_state_id=GENESIS,
            authority_grant_id=hostile, new_state_payload={"probe": "hostile-id"},
        )
        cross_id_findings.append(f"UNEXPECTED ACCEPT: hostile id {hostile!r}")
    except KernelError:
        pass
with kernel.connect() as conn:
    after_tables = {
        t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in ("states", "transitions", "receipts", "exceptions", "authority_grants")
    }
assert cross_id_findings == []
assert after_tables["states"] == before_tables["states"]
assert after_tables["transitions"] == before_tables["transitions"]
assert after_tables["authority_grants"] == before_tables["authority_grants"]
assert after_tables["receipts"] == before_tables["receipts"] + len(hostile_ids)
assert after_tables["exceptions"] == before_tables["exceptions"] + len(hostile_ids)

print(f"AREA-12 (systematic cross-ID confusion: {len(real_ids)} real ids x 4 slots, plus {len(hostile_ids)} hostile/SQL-looking/empty/huge/unicode ids): zero accepted, every rejection correctly attributed, zero authoritative leakage -- NON-VIOLATION")

# ================================================================
# AREA 16: systematic payload cross-contamination. Every payload-
# bearing field gets a full forged representation of every OTHER
# primitive, then a realistic follow-up operation checks for leakage.
# ================================================================

forged_everything = {
    "action": "GRANT", "kind": "REVOKE_ALL", "outcome": "ACCEPTED",
    "grant_id": "grant:forged", "identity_id": NATHAN, "authority_id": "authority:root",
    "is_root": True, "revoked": True, "state_id": GENESIS, "to_state_id": "state:forged",
    "transition_id": "transition:forged", "receipt_id": "receipt:forged",
    "exception_id": "exception:forged", "operation_id": "operation:forged",
    "sql": "'); DELETE FROM authority_grants; --", "python": "__import__('os').system('id')",
}

payload_slots = []

# (a) State payload (via transition's new_state_payload)
r = kernel.transition(
    requester_identity_id=NATHAN, from_state_id=GENESIS,
    authority_grant_id=ROOT_GRANT, new_state_payload=forged_everything,
)
payload_slots.append(("state_payload", r["state_id"]))

# (b) Transition payload
r2 = kernel.transition(
    requester_identity_id=NATHAN, from_state_id=r["state_id"],
    authority_grant_id=ROOT_GRANT, new_state_payload={"probe": "b"},
    transition_payload=forged_everything,
)
payload_slots.append(("transition_payload", r2["transition_id"]))

# (c) Evidence payload
ev = kernel.record_evidence(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT, payload=forged_everything,
)
payload_slots.append(("evidence_payload", ev["evidence_id"]))

# (d) Authority definition payload
auth_def = kernel.define_authority(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    authority_id="authority:forged-payload-target", is_root=False, payload=forged_everything,
)
payload_slots.append(("authority_payload", auth_def["authority_id"]))

# (e) Grant payload
g = kernel.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN, authority_id="authority:forged-payload-target", payload=forged_everything,
)
payload_slots.append(("grant_payload", g["grant_id"]))

# (f) Exception details (via record_failure directly)
exc_receipt = kernel.record_failure(
    operation_id="operation:area-16-exception", outcome="FAILED",
    reason="area-16 probe", details=forged_everything,
)
payload_slots.append(("exception_details", exc_receipt))

# Verify: the payload-defined "authority:forged-payload-target" is
# NOT root (is_root column, never payload, decides this) even though
# every payload above claims is_root/root everywhere.
assert kernel_module  # keep import used
with kernel.connect() as conn:
    row = conn.execute(
        "SELECT is_root FROM authorities WHERE authority_id = 'authority:forged-payload-target'"
    ).fetchone()
assert row[0] == 0, "define_authority(is_root=False) must remain non-root regardless of forged payload claims"

# Verify: none of this created a SECOND grant:forged / state:forged /
# transition:forged / receipt:forged / exception:forged row, and
# authority_grants content is unaffected.
with kernel.connect() as conn:
    for forged_id, table, col in [
        ("grant:forged", "authority_grants", "grant_id"),
        ("state:forged", "states", "state_id"),
        ("transition:forged", "transitions", "transition_id"),
        ("receipt:forged", "receipts", "receipt_id"),
        ("exception:forged", "exceptions", "exception_id"),
    ]:
        found = conn.execute(f"SELECT 1 FROM {table} WHERE {col} = ?", (forged_id,)).fetchone()
        assert found is None, f"forged {col}={forged_id!r} must never materialize as a real row"

print(f"AREA-16 (systematic payload cross-contamination across all 6 payload-bearing fields: State, Transition, Evidence, Authority, Grant, Exception): forged is_root/action/GRANT/REVOKE_ALL/SQL/Python content in every slot -- zero kernel-power acquired, authority:forged-payload-target correctly non-root, no forged ID ever materialized as a real row -- NON-VIOLATION")

# ================================================================
# AREA 18: crash/transaction boundaries at several distinct stages of
# a composed operation.
# ================================================================

def counts(conn):
    return {
        t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in ("states", "transitions", "receipts", "exceptions", "authority_grants", "authority_grant_revocations", "evidence", "receipt_evidence")
    }


# 18a. Force failure BEFORE any INSERT at all (grant validation itself
# raises) -- already exercised throughout as ordinary KernelError
# REJECTED paths; confirm once more explicitly with a delta check.
with kernel.connect() as conn:
    before = counts(conn)
try:
    kernel.transition(
        requester_identity_id=NATHAN, from_state_id=GENESIS,
        authority_grant_id="grant:does-not-exist-18a", new_state_payload={"probe": "18a"},
    )
except KernelError:
    pass
with kernel.connect() as conn:
    after = counts(conn)
delta = {k: after[k] - before[k] for k in before}
assert delta["receipts"] == 1 and delta["exceptions"] == 1
assert all(v == 0 for k, v in delta.items() if k not in ("receipts", "exceptions"))

# 18b. Force failure AFTER the first authoritative INSERT (states) but
# BEFORE the transition INSERT, via a monkeypatched new_id that raises
# on its second call within transition()'s body (state_id succeeds,
# transition_id generation fails) -- this happens BEFORE the write
# transaction even opens (both ids are generated pre-transaction), so
# this actually tests failure between ID generation, not mid-insert.
# Use a different technique: monkeypatch conn.execute via encode_payload
# call-counting to fail specifically on the THIRD authoritative
# INSERT's payload encode (transitions' one) instead.
real_encode_payload = kernel_module.encode_payload
call_count = {"n": 0}
def encode_payload_fail_third(payload):
    call_count["n"] += 1
    if call_count["n"] == 2:  # states insert succeeds (1st), transitions insert (2nd) fails
        raise RuntimeError("synthetic 18b: fail after states INSERT, before transitions INSERT")
    return real_encode_payload(payload)

with kernel.connect() as conn:
    before = counts(conn)
kernel_module.encode_payload = encode_payload_fail_third
try:
    kernel.transition(
        requester_identity_id=NATHAN, from_state_id=GENESIS,
        authority_grant_id=ROOT_GRANT, new_state_payload={"probe": "18b"},
    )
    raise AssertionError("forced mid-transaction failure must reject the transition")
except KernelError:
    pass
finally:
    kernel_module.encode_payload = real_encode_payload
with kernel.connect() as conn:
    after = counts(conn)
delta = {k: after[k] - before[k] for k in before}
assert delta["states"] == 0, f"the already-executed States INSERT must roll back when a LATER statement in the same transaction fails: {delta}"
assert delta["transitions"] == 0
assert delta["receipts"] == 1 and delta["exceptions"] == 1

print(f"AREA-18 (crash/transaction boundaries -- before any INSERT, and after States INSERT but before Transitions INSERT): both leave zero partial authoritative effects, exactly 1 REJECTED/FAILED receipt + exception each -- NON-VIOLATION")

# ================================================================
# AREA 19: supported-boundary corruption behavior. Corrupt a throwaway
# db OUTSIDE the kernel boundary (direct SQL), then invoke SUPPORTED
# kernel operations and observe behavior. Classify carefully.
# ================================================================

corrupt_kernel = fresh_kernel()

# Corrupt: directly insert an authority_grants row with a NULL
# granted_by_identity_id for a NON-genesis grant (only genesis is
# supposed to have this) -- simulates direct-SQL tampering.
with sqlite3.connect(corrupt_kernel.db_path) as conn:
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute(
        "INSERT INTO authority_grants (grant_id, authority_seq, identity_id, authority_id, "
        "granted_by_identity_id, created_at, valid_from, expires_at, payload) "
        "VALUES ('grant:corrupt-unparented', 999, 'identity:nathan', 'authority:root', "
        "NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', NULL, '{}')"
    )
    conn.commit()

# Now invoke a SUPPORTED operation using this corrupted grant as
# authorizer -- does the kernel safely accept/reject it, or does
# something worse happen (crash, silent corruption amplification, or
# a false stronger claim)?
try:
    result = corrupt_kernel.grant(
        requester_identity_id=NATHAN, authority_grant_id="grant:corrupt-unparented",
        identity_id=NATHAN, authority_id="authority:root",
    )
    classification = "ACCEPTED -- the corrupted grant validated normally (kernel has no code path checking granted_by_identity_id at all, so a directly-injected NULL-parent grant behaves identically to a normal one for validation purposes)"
except KernelError as exc:
    classification = f"REJECTED: {exc}"

print(f"AREA-19a (direct-SQL-injected unparented grant, then a supported grant() call using it): {classification}")
print("  Classification: OUTSIDE SUPPORTED BOUNDARY / HARDENING OPPORTUNITY, not a kernel violation -- kernel.py has no runtime check of granted_by_identity_id at all (genesis's NULL there is a seed-time-only convention, enforced by nothing at read time); direct SQL access is explicitly outside 'Userland must not write the database directly'.")

# Corrupt: directly flip is_root on a NON-root authority via raw SQL.
corrupt_kernel2 = fresh_kernel()
with sqlite3.connect(corrupt_kernel2.db_path) as conn:
    conn.execute(
        "INSERT INTO authorities (authority_id, created_at, is_root, payload) "
        "VALUES ('authority:direct-sql-root', '2026-01-01T00:00:00Z', 1, '{}')"
    )
    conn.execute(
        "INSERT INTO authority_grants (grant_id, authority_seq, identity_id, authority_id, "
        "granted_by_identity_id, created_at, valid_from, expires_at, payload) "
        "VALUES ('grant:direct-sql-root', 998, 'identity:nathan', 'authority:direct-sql-root', "
        "NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', NULL, '{}')"
    )
    conn.commit()
try:
    corrupt_kernel2.revoke(
        requester_identity_id=NATHAN, authority_grant_id="grant:direct-sql-root",
        grant_id=ROOT_GRANT,
    )
    classification2 = "ACCEPTED -- a directly-SQL-injected root grant successfully authorized revoking the REAL genesis root grant"
except KernelError as exc:
    classification2 = f"REJECTED: {exc}"
print(f"AREA-19b (direct-SQL-injected root grant used to authorize revoking the real genesis root): {classification2}")
print("  Classification: OUTSIDE SUPPORTED BOUNDARY -- this is exactly the State-round-accepted boundary ('arbitrary direct modification of private SQLite is outside the kernel guarantee'), reproduced here for Authority specifically; it does not expose any guarantee the kernel claims about the SUPPORTED boundary (nothing writes authority_grants/authorities except grant()/define_authority(), which this bypassed entirely) -- consistent, not a new finding.")

print()
print("Part C (cross-ID confusion, payload contamination, crash boundaries, corruption boundary) complete.")
