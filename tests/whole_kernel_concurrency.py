"""Whole-kernel composition review, Part B: concurrency / TOCTOU.

Attack area 5: revocation race. Uses real threads (not just sequential
simulation) against a fresh genesis db, injecting an artificial delay
inside a transition()'s write transaction (between grant validation and
commit) via monkeypatching kernel.encode_payload, while a concurrent
thread attempts to revoke that same grant. SQLite's BEGIN IMMEDIATE
takes the write lock at transaction start, so this also directly tests
whether the kernel's single-writer serialization claim actually holds
under real concurrent access, not just "no test happened to interleave
them."
"""

from __future__ import annotations

import subprocess
import tempfile
import threading
import time
from pathlib import Path

import kernel as kernel_module
from kernel import Kernel, KernelError

REPO = Path(__file__).resolve().parent.parent
GENESIS_SEED = Path(__file__).resolve().parent / "fixtures" / "genesis_seed.sql"
NATHAN = "identity:nathan"
ROOT_GRANT = "grant:genesis-root"
GENESIS = "state:genesis"


def fresh_kernel() -> Kernel:
    f = tempfile.NamedTemporaryFile(prefix="whole-kernel-concurrency-", suffix=".db")
    f.close()
    db_path = Path(f.name)
    subprocess.run(["sqlite3", str(db_path)], stdin=open(REPO / "schema.sql"), check=True)
    subprocess.run(["sqlite3", str(db_path)], stdin=open(GENESIS_SEED), check=True)
    return Kernel(db_path)


# ================================================================
# RACE 1: transition() vs revoke() on the SAME grant, real threads.
#
# Delay is injected inside transition()'s write transaction, AFTER
# grant validation has already run (inside BEGIN IMMEDIATE, so the
# write lock is already held), by monkeypatching encode_payload
# (called once per INSERT) to sleep on its first invocation within
# this transition only.
# ================================================================

kernel = fresh_kernel()

worker_grant = kernel.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN, authority_id="authority:root",
)["grant_id"]
# reuse root's own second grant as the target of the race so requester
# identity matches without extra setup
RACE_GRANT = worker_grant

real_encode_payload = kernel_module.encode_payload
delay_armed = {"on": False, "fired": False}


def encode_payload_delayed(payload):
    if delay_armed["on"] and not delay_armed["fired"]:
        delay_armed["fired"] = True
        time.sleep(0.4)
    return real_encode_payload(payload)


results = {}


def do_transition():
    kernel_module.encode_payload = encode_payload_delayed
    delay_armed["on"] = True
    try:
        results["transition"] = kernel.transition(
            requester_identity_id=NATHAN, from_state_id=GENESIS,
            authority_grant_id=RACE_GRANT, new_state_payload={"race": "1"},
        )
        results["transition_error"] = None
    except KernelError as exc:
        results["transition"] = None
        results["transition_error"] = str(exc)
    finally:
        kernel_module.encode_payload = real_encode_payload


def do_revoke():
    time.sleep(0.1)  # let the transition thread acquire BEGIN IMMEDIATE first
    revoke_started_at = time.time()
    try:
        results["revoke"] = kernel.revoke(
            requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
            grant_id=RACE_GRANT, reason="race probe",
        )
        results["revoke_error"] = None
    except KernelError as exc:
        results["revoke"] = None
        results["revoke_error"] = str(exc)
    results["revoke_duration"] = time.time() - revoke_started_at


t1 = threading.Thread(target=do_transition)
t2 = threading.Thread(target=do_revoke)
t1.start()
t2.start()
t1.join(timeout=10)
t2.join(timeout=10)

print("RACE-1 results:")
print(f"  transition: {'ACCEPTED ' + results['transition']['transition_id'] if results.get('transition') else 'REJECTED/FAILED: ' + str(results.get('transition_error'))}")
print(f"  revoke: {'ACCEPTED ' + results['revoke']['receipt_id'] if results.get('revoke') else 'REJECTED/FAILED: ' + str(results.get('revoke_error'))}")
print(f"  revoke blocked for ~{results['revoke_duration']:.2f}s (transition held the write lock for ~0.4s)")

assert results["revoke"] is not None, "revoke itself must succeed (nothing prevents revoking a grant mid-use)"
assert results["revoke_duration"] >= 0.2, (
    f"revoke should have been forced to wait for the transition's write "
    f"lock (held ~0.4s) rather than interleaving -- got {results['revoke_duration']:.2f}s, "
    f"suggests SQLite's BEGIN IMMEDIATE serialization did NOT actually block the second writer"
)

# The critical correctness question: regardless of which one committed
# first, is the FINAL state coherent? If the transition committed
# BEFORE the revoke (raced in and got the lock first), that's fine --
# it validated against a still-valid grant at its own serialization
# point, and the revoke afterward correctly does not retroactively
# undo it. If the revoke won the race, the transition (which started
# its own BEGIN IMMEDIATE first per the 0.1s head start, so this
# shouldn't happen given SQLite's FIFO-ish lock queueing, but verify
# anyway) must show REJECTED, not a corrupted partial state.
if results["transition"] is not None:
    # transition committed. Its own grant validation happened while
    # holding the lock, so this is coherent by construction -- but
    # confirm the grant now correctly shows revoked for ANY future use.
    assert kernel.is_grant_revoked(RACE_GRANT) is True
    print("  OUTCOME: transition committed first (held the lock, validated + committed atomically), revoke applied after -- COHERENT")
else:
    assert "revoked" in results["transition_error"], (
        f"if the transition lost the race, it must fail because the grant "
        f"was already revoked by the time IT could validate, not some other "
        f"corrupted reason: {results['transition_error']}"
    )
    print("  OUTCOME: revoke committed first, transition correctly re-validated and saw it revoked -- COHERENT")

with kernel.connect() as conn:
    fk_check = list(conn.execute("PRAGMA foreign_key_check").fetchall())
    integrity = [tuple(r) for r in conn.execute("PRAGMA integrity_check").fetchall()]
assert fk_check == []
assert integrity == [("ok",)]

print("RACE-1 (transition vs revoke on the same grant, real threads): NON-VIOLATION -- SQLite's BEGIN IMMEDIATE genuinely serialized the two writers; whichever committed second correctly re-observed the other's committed effect; no interleaved/partial state")
print()

# ================================================================
# RACE 2: two concurrent transition() calls from the SAME from_state_id
# (branch race) -- both must succeed as independent coherent branches,
# never corrupt/merge/lose one.
# ================================================================

kernel2 = fresh_kernel()
branch_results = {}


def do_branch(tag):
    branch_results[tag] = kernel2.transition(
        requester_identity_id=NATHAN, from_state_id=GENESIS,
        authority_grant_id=ROOT_GRANT, new_state_payload={"branch_race": tag},
    )


threads = [threading.Thread(target=do_branch, args=(tag,)) for tag in ("X", "Y", "Z")]
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=10)

state_ids = {branch_results[tag]["state_id"] for tag in ("X", "Y", "Z")}
transition_ids = {branch_results[tag]["transition_id"] for tag in ("X", "Y", "Z")}
assert len(state_ids) == 3 and len(transition_ids) == 3, "all three concurrent branches must be distinct"

with kernel2.connect() as conn:
    outgoing = conn.execute(
        "SELECT COUNT(*) FROM transitions WHERE from_state_id = ?", (GENESIS,)
    ).fetchone()[0]
    fk_check2 = list(conn.execute("PRAGMA foreign_key_check").fetchall())
    integrity2 = [tuple(r) for r in conn.execute("PRAGMA integrity_check").fetchall()]
assert outgoing == 3
assert fk_check2 == []
assert integrity2 == [("ok",)]

print(f"RACE-2 (3 concurrent transitions from the same from_state_id): all 3 committed as distinct branches, no lost update, no corruption -- NON-VIOLATION")
print()

# ================================================================
# RACE 3: two concurrent revoke() calls, each targeting a DIFFERENT
# one of the last two valid root grants, at the SAME time -- the
# last-root guard must hold under real concurrency, not just when
# tested sequentially. Exactly one must succeed; the other must fail.
# ================================================================

kernel3 = fresh_kernel()
root2_grant = kernel3.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN, authority_id="authority:root",
)["grant_id"]
# two currently-valid root grants now exist: ROOT_GRANT and root2_grant

race3_results = {}


def do_revoke_race(tag, target_grant_id, authorizer_grant_id):
    try:
        race3_results[tag] = kernel3.revoke(
            requester_identity_id=NATHAN, authority_grant_id=authorizer_grant_id,
            grant_id=target_grant_id, reason=f"race-3 {tag}",
        )
        race3_results[f"{tag}_error"] = None
    except KernelError as exc:
        race3_results[tag] = None
        race3_results[f"{tag}_error"] = str(exc)


t_a = threading.Thread(target=do_revoke_race, args=("A", ROOT_GRANT, root2_grant))
t_b = threading.Thread(target=do_revoke_race, args=("B", root2_grant, ROOT_GRANT))
t_a.start()
t_b.start()
t_a.join(timeout=10)
t_b.join(timeout=10)

succeeded = [tag for tag in ("A", "B") if race3_results.get(tag) is not None]
failed = [tag for tag in ("A", "B") if race3_results.get(tag) is None]

print(f"RACE-3 results: succeeded={succeeded}, failed={failed}")
if failed:
    print(f"  failure reason: {race3_results.get(f'{failed[0]}_error')}")

with kernel3.connect() as conn:
    currently_valid_roots = [
        r[0] for r in conn.execute(
            """
            SELECT ag.grant_id FROM authority_grants ag
            JOIN authorities a ON a.authority_id = ag.authority_id
            WHERE a.is_root = 1
            """
        ).fetchall()
        if not kernel3.is_grant_revoked(r[0])
    ]

assert len(currently_valid_roots) >= 1, (
    f"CRITICAL: concurrent revoke race left ZERO valid root grants -- "
    f"the last-root guard was bypassed under real concurrency. "
    f"valid_roots={currently_valid_roots}, succeeded={succeeded}, failed={failed}"
)

with kernel3.connect() as conn:
    fk_check3 = list(conn.execute("PRAGMA foreign_key_check").fetchall())
    integrity3 = [tuple(r) for r in conn.execute("PRAGMA integrity_check").fetchall()]
assert fk_check3 == []
assert integrity3 == [("ok",)]

if len(succeeded) == 2:
    print("RACE-3 FINDING: both concurrent revokes succeeded (each independently saw >=1 other valid root grant at its own serialization point) -- final valid-root count:", len(currently_valid_roots))
    assert len(currently_valid_roots) == 0, "if both succeeded and each legitimately saw the other as still-valid at its own commit point, zero should remain -- checking this matches expectation"
    print("  This means: two sequential (lock-serialized) revokes, each individually valid against the ledger AT ITS OWN moment (the other root grant hadn't been revoked YET when this one's transaction validated), can jointly zero out root administration -- the guard checks 'is there another currently valid root grant RIGHT NOW', which is a true statement at each individual commit, but does not coordinate across two SEPARATE serialized operations.")
else:
    print(f"RACE-3 (concurrent revoke of the two remaining root grants): exactly one succeeded ({succeeded}), the other correctly refused ({failed}) -- last-root guard held under real concurrency -- NON-VIOLATION")

print()
print("Concurrency/TOCTOU probes complete.")
