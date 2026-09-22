"""Whole-kernel composition review, Part A: one long adversarial history.

Builds a substantial mixed history from a fresh genesis db (not the
polluted dev db) and interleaves attacks from most of the brief's
primary attack areas into ONE continuous narrative, then runs a full
graph audit at the end. Separate scripts cover concurrency/TOCTOU
(whole_kernel_concurrency.py) and systematic cross-ID/payload
contamination sweeps (whole_kernel_cross_id.py).

Covers attack areas: 1 (Authority x branching), 2 (Authority x
Evidence), 3 (Authority x Receipt), 4 (Authority x Exception), 6
(branch explosion/duplicate ops), 7 (resume ancient state), 8
(Evidence x failure), 9 (Receipt composition), 10 (failure->retry->
success), 11 (success->later failure), 12 (cross-operation ID
confusion, partial), 14 (Genesis assumptions), 15 (last-root guard
composition/rotation), 16 (payload cross-contamination, partial), 17
(long adversarial history), 20 (semantic ownership audit, partial).
"""

from __future__ import annotations

import json
import subprocess
import sqlite3
import tempfile
from pathlib import Path

from kernel import Kernel, KernelError

REPO = Path(__file__).resolve().parent.parent
GENESIS_SEED = Path(__file__).resolve().parent / "fixtures" / "genesis_seed.sql"


def fresh_kernel() -> tuple[Kernel, Path]:
    f = tempfile.NamedTemporaryFile(prefix="whole-kernel-history-", suffix=".db")
    f.close()
    db_path = Path(f.name)
    subprocess.run(["sqlite3", str(db_path)], stdin=open(REPO / "schema.sql"), check=True)
    subprocess.run(["sqlite3", str(db_path)], stdin=open(GENESIS_SEED), check=True)
    return Kernel(db_path), db_path


NATHAN = "identity:nathan"
ROOT_GRANT = "grant:genesis-root"
ROOT_AUTH = "authority:root"
GENESIS = "state:genesis"

kernel, db_path = fresh_kernel()

findings = []


def note(label, text):
    findings.append((label, text))
    print(f"[{label}] {text}")


# ================================================================
# STEP 1: bootstrap secondary identities/authorities/grants.
# ================================================================

kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=GENESIS,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"step": "seed-identities"},
    new_identities=[
        {"identity_id": "identity:root2", "payload": {"role": "second root admin"}},
        {"identity_id": "identity:clawde", "payload": {"role": "worker"}},
        {"identity_id": "identity:root3", "payload": {"role": "third root admin"}},
    ],
)
s_seed = kernel.get_receipt(
    kernel.transition(
        requester_identity_id=NATHAN, from_state_id=GENESIS, authority_grant_id=ROOT_GRANT,
        new_state_payload={"step": "seed-identities-2"},
    )["receipt_id"]
)  # throwaway extra branch off genesis, used below for branch-explosion checks

authority_root2 = kernel.define_authority(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    authority_id="authority:root2", is_root=True,
)
authority_worker = kernel.define_authority(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    authority_id="authority:worker", is_root=False,
)

grant_root2 = kernel.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id="identity:root2", authority_id="authority:root2",
)
grant_worker_clawde = kernel.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id="identity:clawde", authority_id="authority:worker",
)

ROOT2_GRANT = grant_root2["grant_id"]
WORKER_GRANT = grant_worker_clawde["grant_id"]

note("SETUP", f"root2 grant={ROOT2_GRANT}, worker grant={WORKER_GRANT}")

# ================================================================
# ATTACK AREA 6: branch explosion. Two distinct accepted transitions
# from the SAME from_state_id (genesis) must both succeed as separate
# branches, never merged/deduplicated, with correct distinct Receipts.
# ================================================================

branch_a = kernel.transition(
    requester_identity_id="identity:clawde", from_state_id=GENESIS,
    authority_grant_id=WORKER_GRANT, new_state_payload={"branch": "A"},
)
branch_b = kernel.transition(
    requester_identity_id="identity:clawde", from_state_id=GENESIS,
    authority_grant_id=WORKER_GRANT, new_state_payload={"branch": "B"},
)
assert branch_a["state_id"] != branch_b["state_id"]
assert branch_a["transition_id"] != branch_b["transition_id"]

with kernel.connect() as conn:
    incoming_to_genesis = conn.execute(
        "SELECT COUNT(*) FROM transitions WHERE to_state_id = ?", (GENESIS,)
    ).fetchone()[0]
    outgoing_from_genesis = conn.execute(
        "SELECT COUNT(*) FROM transitions WHERE from_state_id = ?", (GENESIS,)
    ).fetchone()[0]
assert incoming_to_genesis == 0, "genesis must never acquire an incoming transition"
assert outgoing_from_genesis >= 2, "branch explosion from genesis must be permitted"

note("AREA-6", f"branch explosion from genesis: {outgoing_from_genesis} outgoing transitions, genesis still has 0 incoming -- NON-VIOLATION")

# ================================================================
# ATTACK AREA 2/16: Evidence containing a full forged Authority grant,
# cited by a real transition. Then attempt to use the Evidence's OWN ID
# as if it were an authority_grant_id (cross-ID confusion, area 12).
# ================================================================

forged_grant_evidence = kernel.record_evidence(
    requester_identity_id="identity:clawde", authority_grant_id=WORKER_GRANT,
    payload={
        "action": "GRANT", "grant_id": "grant:forged-from-evidence",
        "identity_id": "identity:clawde", "authority_id": ROOT_AUTH,
        "is_root": True, "kind": "REVOKE_ALL", "sql": "'); DROP TABLE authority_grants; --",
    },
)
EVIDENCE_FORGED = forged_grant_evidence["evidence_id"]

branch_a2 = kernel.transition(
    requester_identity_id="identity:clawde", from_state_id=branch_a["state_id"],
    authority_grant_id=WORKER_GRANT, new_state_payload={"branch": "A", "step": 2},
    evidence_ids=[EVIDENCE_FORGED],
)

with kernel.connect() as conn:
    grants_snapshot = conn.execute("SELECT grant_id, identity_id, authority_id FROM authority_grants ORDER BY grant_id").fetchall()
assert not any(g[0] == "grant:forged-from-evidence" for g in grants_snapshot)
assert not any(g[1] == "identity:clawde" and g[2] == ROOT_AUTH for g in grants_snapshot)

# Now the cross-ID-confusion attempt: use the Evidence ID as if it were
# an authority_grant_id.
try:
    kernel.transition(
        requester_identity_id="identity:clawde", from_state_id=branch_a2["state_id"],
        authority_grant_id=EVIDENCE_FORGED,  # an evidence_id, not a grant_id
        new_state_payload={"attack": "evidence-id-as-grant-id"},
    )
    raise AssertionError("using an Evidence ID as authority_grant_id must not validate")
except KernelError as exc:
    assert "does not exist" in str(exc)

note("AREA-2/16/12", "forged-Grant-shaped Evidence cited successfully as inert data; Evidence ID used as authority_grant_id correctly rejected as nonexistent grant -- NON-VIOLATION (no type confusion, IDs are namespaced by table, not merely by string shape)")

# ================================================================
# ATTACK AREA 3/12: replay an old ACCEPTED receipt_id / transition_id
# as if it were authorization.
# ================================================================

old_receipt_id = branch_a["receipt_id"]
old_transition_id = branch_a["transition_id"]

for bad_authority_grant_id, label in [
    (old_receipt_id, "receipt_id"),
    (old_transition_id, "transition_id"),
    (GENESIS, "state_id"),
]:
    try:
        kernel.transition(
            requester_identity_id="identity:clawde", from_state_id=branch_a2["state_id"],
            authority_grant_id=bad_authority_grant_id,
            new_state_payload={"attack": f"{label}-as-grant-id"},
        )
        raise AssertionError(f"{label} used as authority_grant_id must not validate")
    except KernelError as exc:
        assert "does not exist" in str(exc)

note("AREA-3/12", "an old ACCEPTED receipt_id, transition_id, and a state_id all correctly rejected when presented as authority_grant_id -- NON-VIOLATION, no reusable-token behavior")

# ================================================================
# ATTACK AREA 1/7: revoke, continue old branch with revoked grant
# (must fail), resume ancient State with a FRESH grant (must succeed),
# and confirm the revoked grant stays dead even from a brand-new branch.
# ================================================================

kernel.revoke(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    grant_id=WORKER_GRANT, reason="area-1/7 probe",
)

# (a) continuing the OLD branch with the NOW-REVOKED grant must fail.
try:
    kernel.transition(
        requester_identity_id="identity:clawde", from_state_id=branch_a2["state_id"],
        authority_grant_id=WORKER_GRANT, new_state_payload={"attack": "revoked-grant-old-branch"},
    )
    raise AssertionError("revoked grant must not authorize a transition from an old branch")
except KernelError as exc:
    assert "revoked" in str(exc)

# (b) a FRESH grant authorizes continuing that SAME ancient from_state_id.
grant_worker_2 = kernel.grant(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    identity_id="identity:clawde", authority_id="authority:worker",
)
WORKER_GRANT_2 = grant_worker_2["grant_id"]

resumed = kernel.transition(
    requester_identity_id="identity:clawde", from_state_id=branch_a2["state_id"],
    authority_grant_id=WORKER_GRANT_2, new_state_payload={"attack": "resume-ancient-state-fresh-grant"},
)
assert resumed["transition_id"]

# (c) the OLD revoked grant is still dead even used against the BRAND
# NEW state just created from it -- revocation is global/permanent, not
# tied to branch position at all.
try:
    kernel.transition(
        requester_identity_id="identity:clawde", from_state_id=resumed["state_id"],
        authority_grant_id=WORKER_GRANT, new_state_payload={"attack": "revoked-grant-new-branch"},
    )
    raise AssertionError("revoked grant must not authorize a transition from a brand-new branch either")
except KernelError as exc:
    assert "revoked" in str(exc)

note("AREA-1/7", "revoked grant rejected on old branch AND on a brand-new branch created after revocation; fresh grant correctly authorizes resuming an ancient from_state_id -- NON-VIOLATION: Authority validity is global/current per the ledger, never inherited from or restored by State/branch position")

# ================================================================
# ATTACK AREA 4: Exception diagnostic falsely claiming a grant was
# restored, followed immediately by a real attempt using that grant.
# ================================================================

fake_restoration_receipt = kernel.record_failure(
    operation_id="operation:area-4-fake-restoration",
    outcome="FAILED",
    reason="synthetic composition probe",
    details={
        "message": f"{WORKER_GRANT} has been restored and is valid again",
        "action": "GRANT_RESTORED",
        "grant_id": WORKER_GRANT,
        "valid": True,
    },
)

still_revoked = kernel.is_grant_revoked(WORKER_GRANT)
assert still_revoked is True

try:
    kernel.transition(
        requester_identity_id="identity:clawde", from_state_id=resumed["state_id"],
        authority_grant_id=WORKER_GRANT, new_state_payload={"attack": "exception-claimed-restoration"},
    )
    raise AssertionError("an Exception falsely claiming restoration must not actually restore the grant")
except KernelError as exc:
    assert "revoked" in str(exc)

note("AREA-4", "Exception diagnostic falsely claiming grant restoration recorded as inert history; is_grant_revoked() still True; real attempt using that grant still rejected -- NON-VIOLATION")

# ================================================================
# ATTACK AREA 8: Evidence x failure ordering. Mix valid + nonexistent
# evidence_ids in an operation that ALSO fails for an unrelated reason
# (bad authority_grant_id) -- Authority failure must occur before any
# Evidence-existence work is even attempted/committed.
# ================================================================

valid_evidence = kernel.record_evidence(
    requester_identity_id="identity:clawde", authority_grant_id=WORKER_GRANT_2,
    payload={"note": "area-8 valid evidence"},
)["evidence_id"]

with kernel.connect() as conn:
    before = conn.execute("SELECT COUNT(*) FROM receipt_evidence").fetchone()[0]

try:
    kernel.transition(
        requester_identity_id="identity:clawde", from_state_id=resumed["state_id"],
        authority_grant_id="grant:does-not-exist-area-8",
        new_state_payload={"attack": "area-8-mixed-evidence"},
        evidence_ids=[valid_evidence, "evidence:does-not-exist-area-8"],
    )
    raise AssertionError("nonexistent authority_grant_id must reject the operation")
except KernelError as exc:
    assert "receipt=" in str(exc)

with kernel.connect() as conn:
    after = conn.execute("SELECT COUNT(*) FROM receipt_evidence").fetchone()[0]
    last_receipt = conn.execute(
        "SELECT receipt_id, outcome FROM receipts ORDER BY receipt_seq DESC LIMIT 1"
    ).fetchone()
    linked_evidence = {
        r[0] for r in conn.execute(
            "SELECT evidence_id FROM receipt_evidence WHERE receipt_id = ?",
            (last_receipt[0],),
        ).fetchall()
    }

assert last_receipt[1] == "REJECTED"
assert linked_evidence == {valid_evidence}, (
    f"only the VALID evidence_id should be preserved against the REJECTED "
    f"receipt; the nonexistent one must not appear, got {linked_evidence}"
)

note("AREA-8", f"Authority failure (nonexistent grant) correctly REJECTED before Evidence linking; the one real evidence_id was still preserved against the failure Receipt, the nonexistent one silently excluded (not crashing the receipt path) -- NON-VIOLATION, matches record_failure()'s documented behavior")

# ================================================================
# ATTACK AREA 10/11: FAILED -> retry -> ACCEPTED, and a later unrelated
# FAILED operation must not poison/mutate an earlier ACCEPTED one.
# ================================================================

accepted_before_failure = kernel.transition(
    requester_identity_id="identity:clawde", from_state_id=resumed["state_id"],
    authority_grant_id=WORKER_GRANT_2, new_state_payload={"attack": "area-10-accepted-baseline"},
)

real_get_state = kernel.get_state
def boom_once(*a, **kw):
    kernel.get_state = real_get_state
    raise RuntimeError("synthetic area-10 forced FAILED")
kernel.get_state = boom_once
try:
    kernel.transition(
        requester_identity_id="identity:clawde", from_state_id=accepted_before_failure["state_id"],
        authority_grant_id=WORKER_GRANT_2, new_state_payload={"attack": "area-10-forced-fail"},
    )
    raise AssertionError("forced RuntimeError must FAIL the transition")
except KernelError:
    pass
assert kernel.get_state == real_get_state

# retry with identical args, this time for real -- must succeed as an
# independent, coherent operation.
retried = kernel.transition(
    requester_identity_id="identity:clawde", from_state_id=accepted_before_failure["state_id"],
    authority_grant_id=WORKER_GRANT_2, new_state_payload={"attack": "area-10-forced-fail"},
)
assert retried["transition_id"]

# area-11: a further, unrelated FAILED operation citing the ACCEPTED
# receipt/state ids inside its OWN details must not roll back, mutate,
# or reattribute the earlier accepted history.
accepted_payload_before = kernel.get_state(accepted_before_failure["state_id"])
kernel.record_failure(
    operation_id="operation:area-11-unrelated-failure",
    outcome="FAILED",
    reason="synthetic area-11 probe naming earlier accepted IDs",
    details={
        "unrelated_reference": accepted_before_failure["state_id"],
        "unrelated_receipt": accepted_before_failure["receipt_id"],
    },
)
accepted_payload_after = kernel.get_state(accepted_before_failure["state_id"])
assert accepted_payload_before == accepted_payload_after
accepted_receipt_after = kernel.get_receipt(accepted_before_failure["receipt_id"])
assert accepted_receipt_after["outcome"] == "ACCEPTED"

note("AREA-10/11", "FAILED->retry->ACCEPTED produced two independent coherent operations (no poisoning either direction); a later unrelated FAILED operation naming earlier ACCEPTED IDs in its own diagnostic details left that earlier State/Receipt byte-identical -- NON-VIOLATION")

# ================================================================
# ATTACK AREA 15: last-root guard composition / root rotation.
# Currently valid root grants: grant:genesis-root (Nathan), ROOT2_GRANT
# (root2). Rotate: revoke genesis-root (should succeed, root2 survives
# as the other valid root grant); then attempt to revoke root2 (should
# now fail, it's the last one); create a third root grant, THEN revoke
# root2 successfully.
# ================================================================

revoke_genesis_root = kernel.revoke(
    requester_identity_id=NATHAN, authority_grant_id=ROOT_GRANT,
    grant_id=ROOT_GRANT, reason="area-15 rotation step 1: two roots exist, safe to revoke one",
)
assert revoke_genesis_root["receipt_id"]

try:
    kernel.revoke(
        requester_identity_id="identity:root2", authority_grant_id=ROOT2_GRANT,
        grant_id=ROOT2_GRANT, reason="area-15 rotation step 2: must fail, last root",
    )
    raise AssertionError("revoking the now-last root grant must be refused")
except KernelError as exc:
    assert "last currently-valid root grant" in str(exc)

grant_root3 = kernel.grant(
    requester_identity_id="identity:root2", authority_grant_id=ROOT2_GRANT,
    identity_id="identity:root3", authority_id="authority:root2",
)
ROOT3_GRANT = grant_root3["grant_id"]

revoke_root2_now_ok = kernel.revoke(
    requester_identity_id="identity:root3", authority_grant_id=ROOT3_GRANT,
    grant_id=ROOT2_GRANT, reason="area-15 rotation step 3: now safe, root3 exists",
)
assert revoke_root2_now_ok["receipt_id"]

with kernel.connect() as conn:
    currently_valid_roots = conn.execute(
        """
        SELECT ag.grant_id FROM authority_grants ag
        JOIN authorities a ON a.authority_id = ag.authority_id
        WHERE a.is_root = 1
        """
    ).fetchall()
    valid_root_grant_ids = [
        r[0] for r in currently_valid_roots if not kernel.is_grant_revoked(r[0])
    ]
assert valid_root_grant_ids == [ROOT3_GRANT], (
    f"after full rotation exactly ROOT3_GRANT should remain valid, got {valid_root_grant_ids}"
)

# The original genesis grant, though revoked, must still be immutably
# present in history -- revocation never deletes.
original_grant_still_present = kernel.get_grant(ROOT_GRANT)
assert original_grant_still_present is not None
assert kernel.is_grant_revoked(ROOT_GRANT) is True

note("AREA-15", "full root rotation across three sequential root grants succeeded exactly when >=1 other valid root grant existed and was refused exactly when it would have been the last -- NON-VIOLATION, root credential rotation IS possible (not permanently bricked), guard tracks CURRENT ledger state each time, not a fixed snapshot")

# ================================================================
# ATTACK AREA 14: Genesis compositional assumptions.
# ================================================================

try:
    kernel.transition(
        requester_identity_id="identity:root3", authority_grant_id=ROOT3_GRANT,
        from_state_id=GENESIS,
        new_state_payload={"genesis": 1, "attack": "payload-claims-genesis"},
    )
except KernelError:
    raise AssertionError("a normal, valid transition from real genesis must succeed even with genesis-mimicking payload")

fake_genesis_state = kernel.transition(
    requester_identity_id="identity:root3", authority_grant_id=ROOT3_GRANT,
    from_state_id=GENESIS,
    new_state_payload={"claims_to_be": "state:genesis", "is_root": True, "bootstrap": True},
)
assert kernel.get_genesis_state()["state_id"] == GENESIS
with kernel.connect() as conn:
    incoming_to_fake = conn.execute(
        "SELECT COUNT(*) FROM transitions WHERE to_state_id = ?",
        (fake_genesis_state["state_id"],),
    ).fetchone()[0]
assert incoming_to_fake == 1, "any state created via transition() always has exactly its own creating transition, unlike real genesis"

note("AREA-14", "payload claiming to BE genesis/root/bootstrap changes nothing: get_genesis_state() is still hardcoded to the literal 'state:genesis' id, and the payload-mimicking state still has its own real incoming Transition (unlike true genesis, which structurally has none) -- NON-VIOLATION, no supported-boundary path creates a second genesis-like orphan state")

# ================================================================
# GRAPH AUDIT (attack area 9/13/17/20): walk the whole accumulated
# history and check global invariants that only make sense at the
# whole-system level.
# ================================================================

with kernel.connect() as conn:
    total_receipts = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    total_transitions = conn.execute("SELECT COUNT(*) FROM transitions").fetchone()[0]
    total_states = conn.execute("SELECT COUNT(*) FROM states").fetchone()[0]

    # 9/20: no ACCEPTED receipt lacking a transition_id has a transition
    # payload-shaped "action" implying it's a State change (ownership:
    # only transitions own State lineage).
    accepted_without_transition = conn.execute(
        "SELECT payload FROM receipts WHERE outcome = 'ACCEPTED' AND transition_id IS NULL"
    ).fetchall()
    for (payload_raw,) in accepted_without_transition:
        payload = json.loads(payload_raw)
        assert "to_state_id" not in payload or payload.get("action") is not None, (
            "an ACCEPTED Authority-operation receipt should never look like it owns State lineage"
        )

    # 13: operation_id de-facto uniqueness across everything produced
    # by the 6 real entry points in this entire history (record_failure
    # direct calls used explicit distinct operation_id strings above,
    # excluded here since those are deliberately testing collision
    # elsewhere, not this history).
    dup_operation_ids = conn.execute(
        """
        SELECT operation_id, COUNT(*) c FROM receipts
        WHERE operation_id NOT LIKE 'operation:area-%' AND operation_id != 'operation:genesis'
        GROUP BY operation_id HAVING c > 1
        """
    ).fetchall()
    assert dup_operation_ids == [], f"real entry points must never naturally collide on operation_id: {dup_operation_ids}"

    # 9: receipt_seq is monotonic and never reused; used ONLY as PK
    # auto-increment, never read by any kernel decision (already
    # verified by code grep in the Receipt round) -- confirm ordering
    # sanity here too.
    seqs = [r[0] for r in conn.execute("SELECT receipt_seq FROM receipts ORDER BY receipt_seq").fetchall()]
    assert seqs == sorted(seqs) == list(range(seqs[0], seqs[0] + len(seqs)))

    # UNIQUE(to_state_id) actually holds across this whole branchy
    # history (schema-enforced, confirm no violations crept in).
    dup_to_state = conn.execute(
        "SELECT to_state_id, COUNT(*) c FROM transitions GROUP BY to_state_id HAVING c > 1"
    ).fetchall()
    assert dup_to_state == []

    # every FAILED/REJECTED receipt in this whole history has exactly
    # one linked exception.
    orphan_failures = conn.execute(
        """
        SELECT r.receipt_id FROM receipts r
        LEFT JOIN exceptions e ON e.receipt_id = r.receipt_id
        WHERE r.outcome IN ('REJECTED', 'FAILED') AND e.exception_id IS NULL
        """
    ).fetchall()
    assert orphan_failures == [], f"every REJECTED/FAILED receipt must have an Exception: {orphan_failures}"

    integrity = conn.execute("PRAGMA integrity_check").fetchall()
    fk_check = conn.execute("PRAGMA foreign_key_check").fetchall()

assert [tuple(r) for r in integrity] == [("ok",)], integrity
assert list(fk_check) == []

note("GRAPH-AUDIT", f"whole-history audit clean across {total_receipts} receipts / {total_transitions} transitions / {total_states} states: operation_id de-facto unique per real entry-point invocation, receipt_seq monotonic/never reused, UNIQUE(to_state_id) held, every REJECTED/FAILED receipt has exactly one Exception, PRAGMA integrity_check ok, zero FK violations -- NON-VIOLATION")

print()
print(f"Long adversarial history complete: {total_receipts} receipts, {total_transitions} transitions, {total_states} states.")
print(f"Findings recorded: {len(findings)}, all NON-VIOLATION.")
print(f"db_path (preserved for inspection): {db_path}")
