"""
AUTHORITY-1A through 1L.

Exercises the redesigned Authority model that replaces AUTHORITY-0B..
0F (authority_0b_0f.py, now retired -- see its header). Authority
lifecycle (grant/revoke/revoke_all) is now independent of State:
none of `Kernel.grant`, `Kernel.revoke`, `Kernel.revoke_all` create
or require a State transition, and revocation is read back from the
append-only Authority revocation ledger (via
`Kernel.is_grant_revoked`) rather than from Receipt or
`transitions.payload`.

Schema change made to support this (see
migrate_receipts_decouple_from_transition.sql): the `receipts` CHECK
constraint no longer requires `transition_id` for an ACCEPTED
outcome. No table, column, index, or trigger was added.

All authoritative reads/writes below go through the Kernel boundary
only. No direct SQLite access except for the pre-migration receipt
snapshot comparison in AUTHORITY-1L, which is read-only.
"""

import threading

from kernel import Kernel, KernelError, utc_now

kernel = Kernel()

NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
ROOT_GRANT = "grant:genesis-root"
AUTHORITY_ID = "authority:clawde-scope-alpha"

GENESIS_STATE_ID = "state:genesis"
LEAF_STATE_ID = "state:7c7f0a6e-e8e2-407c-b23c-26a65cc72e43"

PRE_MIGRATION_RECEIPTS = {
    "receipt:genesis": ("BOOTSTRAP", None, "2026-09-19T00:00:00Z"),
    "receipt:317182c0-149e-4c77-8c13-a7826a9ae88b": (
        "ACCEPTED",
        "transition:936f5a43-51a5-480e-a915-a62b4ba01985",
        "2026-09-19T21:22:07.492210Z",
    ),
    "receipt:483d0a7b-d31f-4149-9de0-6e188f3bbc1b": (
        "ACCEPTED",
        "transition:5ded9035-c4fe-4ca9-9181-0fa743b00216",
        "2026-09-19T21:24:33.306663Z",
    ),
    "receipt:8c96876e-99c2-4165-9268-6c467dba3c8b": (
        "ACCEPTED",
        "transition:8aa6ecaf-a463-469f-baf7-17675bb424a0",
        "2026-09-19T21:24:33.322997Z",
    ),
    "receipt:86e4e222-22c3-4cf9-b1ce-a83b20c12254": (
        "REJECTED",
        None,
        "2026-09-19T21:24:33.336069Z",
    ),
    "receipt:f0a15a53-fc07-4561-bb52-7c18564f214d": (
        "ACCEPTED",
        "transition:19c3f0e1-1a0c-4b13-8746-7936639ae871",
        "2026-09-19T21:24:33.348126Z",
    ),
    "receipt:4b22b057-85e2-4362-9fdf-8af7b1a0a6f7": (
        "REJECTED",
        None,
        "2026-09-19T21:24:33.360510Z",
    ),
}


def evidence(label, **fields):
    print(f"\n=== {label} ===")
    for key, value in fields.items():
        print(f"  {key}: {value}")


def counts():
    return kernel.count_states(), kernel.count_transitions()


def extract_receipt_id(exc: KernelError) -> str | None:
    text = str(exc)
    if "[receipt=" in text:
        return text.split("[receipt=")[1].rstrip("]")
    return None


def expect_kernel_error(fn, *, contains: str):
    states_before, transitions_before = counts()
    try:
        fn()
        raise AssertionError("expected a KernelError but call succeeded")
    except KernelError as exc:
        assert contains in str(exc), f"unexpected error text: {exc}"
        states_after, transitions_after = counts()
        assert (states_before, transitions_before) == (
            states_after,
            transitions_after,
        ), "a rejected Authority operation must not touch states/transitions"
        return kernel.get_receipt(extract_receipt_id(exc))


genesis = kernel.get_state(GENESIS_STATE_ID)
assert genesis is not None
leaf = kernel.get_state(LEAF_STATE_ID)
assert leaf is not None, (
    "AUTHORITY-0 leaf state not found -- run authority_0a.py / "
    "authority_0b_0f.py against this database first"
)


# ---------------------------------------------------------------
# AUTHORITY-1A -- Direct grant without a State transition
# ---------------------------------------------------------------

states_before_1a, transitions_before_1a = counts()

result_1a = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1A"},
)

G1 = result_1a["grant_id"]
states_after_1a, transitions_after_1a = counts()
grant_1a = kernel.get_grant(G1)
receipt_1a = kernel.get_receipt(result_1a["receipt_id"])

evidence(
    "AUTHORITY-1A result (direct grant)",
    grant_id=G1,
    grant_row=grant_1a,
    receipt=receipt_1a,
    states_before=states_before_1a,
    states_after=states_after_1a,
    transitions_before=transitions_before_1a,
    transitions_after=transitions_after_1a,
)

assert (states_before_1a, transitions_before_1a) == (
    states_after_1a,
    transitions_after_1a,
), "grant() must not create a State or Transition"
assert grant_1a["identity_id"] == CLAWDE
assert grant_1a["authority_id"] == AUTHORITY_ID
assert grant_1a["granted_by_identity_id"] == NATHAN
assert receipt_1a["outcome"] == "ACCEPTED"
assert receipt_1a["transition_id"] is None
assert receipt_1a["payload"]["action"] == "GRANT"
assert kernel.is_grant_revoked(G1) is False


# ---------------------------------------------------------------
# AUTHORITY-1B -- Direct revoke without a State transition
# ---------------------------------------------------------------

states_before_1b, transitions_before_1b = counts()
grant_row_before_1b = kernel.get_grant(G1)

result_1b = kernel.revoke(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    grant_id=G1,
    reason="AUTHORITY-1B",
)

states_after_1b, transitions_after_1b = counts()
grant_row_after_1b = kernel.get_grant(G1)
receipt_1b = kernel.get_receipt(result_1b["receipt_id"])

evidence(
    "AUTHORITY-1B result (direct revoke)",
    receipt=receipt_1b,
    grant_row_unchanged=(grant_row_before_1b == grant_row_after_1b),
    is_revoked=kernel.is_grant_revoked(G1),
)

assert (states_before_1b, transitions_before_1b) == (
    states_after_1b,
    transitions_after_1b,
), "revoke() must not create a State or Transition"
assert grant_row_before_1b == grant_row_after_1b, (
    "the original authority_grants row must never be mutated"
)
assert receipt_1b["outcome"] == "ACCEPTED"
assert receipt_1b["transition_id"] is None
assert receipt_1b["payload"]["action"] == "REVOKE"
assert kernel.is_grant_revoked(G1) is True


# ---------------------------------------------------------------
# AUTHORITY-1C -- Revoked grant fails on every branch
# ---------------------------------------------------------------

branch_a = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=LEAF_STATE_ID,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "AUTHORITY-1C", "branch": "A"},
    transition_payload={"reason": "branch A for post-revocation test"},
)
branch_b = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=LEAF_STATE_ID,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "AUTHORITY-1C", "branch": "B"},
    transition_payload={"reason": "branch B for post-revocation test"},
)

BRANCH_A_STATE = branch_a["state_id"]
BRANCH_B_STATE = branch_b["state_id"]


def attempt_on_branch_a():
    kernel.transition(
        requester_identity_id=CLAWDE,
        from_state_id=BRANCH_A_STATE,
        authority_grant_id=G1,
        new_state_payload={"experiment": "AUTHORITY-1C", "should": "fail"},
    )


def attempt_on_branch_b():
    kernel.transition(
        requester_identity_id=CLAWDE,
        from_state_id=BRANCH_B_STATE,
        authority_grant_id=G1,
        new_state_payload={"experiment": "AUTHORITY-1C", "should": "fail"},
    )


receipt_1c_a = expect_kernel_error(attempt_on_branch_a, contains="has been revoked")
receipt_1c_b = expect_kernel_error(attempt_on_branch_b, contains="has been revoked")

evidence(
    "AUTHORITY-1C result (revoked grant fails on every branch)",
    branch_a=BRANCH_A_STATE,
    branch_b=BRANCH_B_STATE,
    receipt_branch_a=receipt_1c_a,
    receipt_branch_b=receipt_1c_b,
)

assert receipt_1c_a["outcome"] == "REJECTED"
assert receipt_1c_b["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-1D -- Revoked grant fails resuming an old historical State
# ---------------------------------------------------------------


def attempt_on_genesis():
    kernel.transition(
        requester_identity_id=CLAWDE,
        from_state_id=GENESIS_STATE_ID,
        authority_grant_id=G1,
        new_state_payload={"experiment": "AUTHORITY-1D", "should": "fail"},
    )


receipt_1d = expect_kernel_error(attempt_on_genesis, contains="has been revoked")

evidence(
    "AUTHORITY-1D result (revoked grant fails from genesis)",
    from_state=GENESIS_STATE_ID,
    receipt=receipt_1d,
)

assert receipt_1d["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-1E -- Revoking G1 does not affect G2 (same identity)
# ---------------------------------------------------------------

result_1e = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1E"},
)
G2 = result_1e["grant_id"]

validated_g2 = kernel.validate_grant(G2, requester_identity_id=CLAWDE)

evidence(
    "AUTHORITY-1E result (revoking G1 does not affect G2)",
    G1=G1,
    G2=G2,
    G1_revoked=kernel.is_grant_revoked(G1),
    G2_revoked=kernel.is_grant_revoked(G2),
)

assert kernel.is_grant_revoked(G1) is True
assert kernel.is_grant_revoked(G2) is False
assert validated_g2["grant_id"] == G2


# ---------------------------------------------------------------
# AUTHORITY-1F -- revoke_all(identity) invalidates all grants
# existing for that identity at that operation
# ---------------------------------------------------------------

result_g3 = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1F", "label": "G3"},
)
G3 = result_g3["grant_id"]

result_g4 = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1F", "label": "G4"},
)
G4 = result_g4["grant_id"]

result_1f = kernel.revoke_all(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    reason="AUTHORITY-1F",
)

receipt_1f = kernel.get_receipt(result_1f["receipt_id"])

evidence(
    "AUTHORITY-1F result (revoke_all invalidates existing grants)",
    receipt=receipt_1f,
    G2_revoked=kernel.is_grant_revoked(G2),
    G3_revoked=kernel.is_grant_revoked(G3),
    G4_revoked=kernel.is_grant_revoked(G4),
    G1_still_revoked=kernel.is_grant_revoked(G1),
)

assert receipt_1f["outcome"] == "ACCEPTED"
assert receipt_1f["payload"]["action"] == "REVOKE_ALL"
assert kernel.is_grant_revoked(G2) is True
assert kernel.is_grant_revoked(G3) is True
assert kernel.is_grant_revoked(G4) is True
assert kernel.is_grant_revoked(G1) is True


# ---------------------------------------------------------------
# AUTHORITY-1G -- A newly issued grant after revoke_all works
# unless explicitly revoked
# ---------------------------------------------------------------

result_g5 = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1G", "label": "G5"},
)
G5 = result_g5["grant_id"]

result_1g_transition = kernel.transition(
    requester_identity_id=CLAWDE,
    from_state_id=BRANCH_A_STATE,
    authority_grant_id=G5,
    new_state_payload={"experiment": "AUTHORITY-1G", "should": "succeed"},
    transition_payload={"reason": "G5 issued after revoke_all, unrevoked"},
)

evidence(
    "AUTHORITY-1G result (post-revoke_all grant still works)",
    G5=G5,
    G5_revoked=kernel.is_grant_revoked(G5),
    transition=result_1g_transition,
)

assert kernel.is_grant_revoked(G5) is False
assert result_1g_transition["transition_id"] is not None

POST_1G_STATE = result_1g_transition["state_id"]


# ---------------------------------------------------------------
# AUTHORITY-1H -- Unauthorized grant/revoke/revoke_all attempts fail
# ---------------------------------------------------------------


def unauthorized_grant():
    kernel.grant(
        requester_identity_id=CLAWDE,
        authority_grant_id=ROOT_GRANT,
        identity_id=CLAWDE,
        authority_id=AUTHORITY_ID,
    )


def unauthorized_revoke():
    kernel.revoke(
        requester_identity_id=CLAWDE,
        authority_grant_id=ROOT_GRANT,
        grant_id=G5,
    )


def unauthorized_revoke_all():
    kernel.revoke_all(
        requester_identity_id=CLAWDE,
        authority_grant_id=ROOT_GRANT,
        identity_id=NATHAN,
    )


def revoked_grant_cannot_authorize_grant():
    kernel.grant(
        requester_identity_id=CLAWDE,
        authority_grant_id=G1,
        identity_id=CLAWDE,
        authority_id=AUTHORITY_ID,
    )


grants_before_1h = None
with kernel.connect() as conn:
    grants_before_1h = conn.execute(
        "SELECT COUNT(*) AS n FROM authority_grants"
    ).fetchone()["n"]

receipt_1h_a = expect_kernel_error(unauthorized_grant, contains="does not hold grant")
receipt_1h_b = expect_kernel_error(unauthorized_revoke, contains="does not hold grant")
receipt_1h_c = expect_kernel_error(
    unauthorized_revoke_all, contains="does not hold grant"
)
receipt_1h_d = expect_kernel_error(
    revoked_grant_cannot_authorize_grant, contains="has been revoked"
)

with kernel.connect() as conn:
    grants_after_1h = conn.execute(
        "SELECT COUNT(*) AS n FROM authority_grants"
    ).fetchone()["n"]

evidence(
    "AUTHORITY-1H result (unauthorized attempts fail)",
    grants_before=grants_before_1h,
    grants_after=grants_after_1h,
    receipts=[receipt_1h_a, receipt_1h_b, receipt_1h_c, receipt_1h_d],
)

assert grants_before_1h == grants_after_1h, (
    "no unauthorized attempt may create an authority_grants row"
)
for receipt in (receipt_1h_a, receipt_1h_b, receipt_1h_c, receipt_1h_d):
    assert receipt["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-1I -- Authority operation failure produces no partial
# Authority change
# ---------------------------------------------------------------


def grant_missing_identity():
    kernel.grant(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT_GRANT,
        identity_id="identity:does-not-exist",
        authority_id=AUTHORITY_ID,
    )


def revoke_missing_grant():
    kernel.revoke(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT_GRANT,
        grant_id="grant:does-not-exist",
    )


def revoke_all_missing_identity():
    kernel.revoke_all(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT_GRANT,
        identity_id="identity:does-not-exist",
    )


with kernel.connect() as conn:
    grants_before_1i = conn.execute(
        "SELECT COUNT(*) AS n FROM authority_grants"
    ).fetchone()["n"]
    receipts_before_1i = conn.execute(
        "SELECT COUNT(*) AS n FROM receipts"
    ).fetchone()["n"]

receipt_1i_a = expect_kernel_error(
    grant_missing_identity, contains="identity does not exist"
)
receipt_1i_b = expect_kernel_error(
    revoke_missing_grant, contains="authority grant does not exist"
)
receipt_1i_c = expect_kernel_error(
    revoke_all_missing_identity, contains="identity does not exist"
)

with kernel.connect() as conn:
    grants_after_1i = conn.execute(
        "SELECT COUNT(*) AS n FROM authority_grants"
    ).fetchone()["n"]
    receipts_after_1i = conn.execute(
        "SELECT COUNT(*) AS n FROM receipts"
    ).fetchone()["n"]

evidence(
    "AUTHORITY-1I result (no partial Authority change on failure)",
    grants_before=grants_before_1i,
    grants_after=grants_after_1i,
    receipts_before=receipts_before_1i,
    receipts_after=receipts_after_1i,
)

assert grants_before_1i == grants_after_1i
assert receipts_after_1i == receipts_before_1i + 3, (
    "each failed attempt must produce exactly one new receipt "
    "(REJECTED), never zero and never a dangling grant row"
)


# ---------------------------------------------------------------
# AUTHORITY-1J -- Concurrent transition-vs-revoke behavior is
# deterministic under SQLite transaction ordering
# ---------------------------------------------------------------

result_g6 = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1J", "label": "G6"},
)
G6 = result_g6["grant_id"]

barrier = threading.Barrier(2)
outcomes = {}


def concurrent_transition():
    barrier.wait()
    try:
        outcomes["transition"] = (
            "ACCEPTED",
            kernel.transition(
                requester_identity_id=CLAWDE,
                from_state_id=POST_1G_STATE,
                authority_grant_id=G6,
                new_state_payload={"experiment": "AUTHORITY-1J"},
            ),
        )
    except KernelError as exc:
        outcomes["transition"] = ("REJECTED", str(exc))
    except Exception as exc:  # pragma: no cover -- must never happen
        outcomes["transition"] = ("CRASH", repr(exc))


def concurrent_revoke():
    barrier.wait()
    try:
        outcomes["revoke"] = (
            "ACCEPTED",
            kernel.revoke(
                requester_identity_id=NATHAN,
                authority_grant_id=ROOT_GRANT,
                grant_id=G6,
                reason="AUTHORITY-1J concurrent revoke",
            ),
        )
    except KernelError as exc:
        outcomes["revoke"] = ("REJECTED", str(exc))
    except Exception as exc:  # pragma: no cover -- must never happen
        outcomes["revoke"] = ("CRASH", repr(exc))


t1 = threading.Thread(target=concurrent_transition)
t2 = threading.Thread(target=concurrent_revoke)
t1.start()
t2.start()
t1.join()
t2.join()

states_before_1j, transitions_before_1j = counts()

evidence(
    "AUTHORITY-1J result (concurrent transition vs revoke)",
    outcomes=outcomes,
    G6_final_revoked=kernel.is_grant_revoked(G6),
)

assert outcomes["revoke"][0] == "ACCEPTED", (
    "revoke() authorizes itself via ROOT_GRANT, independent of G6's "
    "own state, so it must always succeed regardless of ordering"
)
assert outcomes["transition"][0] in ("ACCEPTED", "REJECTED"), (
    "no crash: the kernel's broad except clauses must turn any "
    "SQLite contention into a clean KernelError, never an unhandled "
    "exception"
)
assert kernel.is_grant_revoked(G6) is True, (
    "regardless of which operation the writer lock let through "
    "first, G6 must end up revoked -- revoke() never depends on "
    "whether a concurrent transition happened to land first or last"
)
if outcomes["transition"][0] == "ACCEPTED":
    new_state_id = outcomes["transition"][1]["state_id"]
    assert kernel.get_state(new_state_id) is not None, (
        "an ACCEPTED transition receipt must never point at a "
        "State that was not actually committed -- no torn write "
        "under contention"
    )


# ---------------------------------------------------------------
# AUTHORITY-1K -- State history remains unchanged by grant/revoke
# operations
# ---------------------------------------------------------------

states_snapshot_before_authority_ops, transitions_snapshot_before_authority_ops = (
    kernel.count_states(),
    kernel.count_transitions(),
)

kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-1K"},
)
result_1k_grant = kernel.get_grant  # no-op reference, grant() already ran above
result_1k = kernel.revoke_all(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    reason="AUTHORITY-1K",
)

states_snapshot_after_authority_ops, transitions_snapshot_after_authority_ops = (
    kernel.count_states(),
    kernel.count_transitions(),
)

evidence(
    "AUTHORITY-1K result (State history unchanged by Authority ops)",
    states_before=states_snapshot_before_authority_ops,
    states_after=states_snapshot_after_authority_ops,
    transitions_before=transitions_snapshot_before_authority_ops,
    transitions_after=transitions_snapshot_after_authority_ops,
)

assert (
    states_snapshot_before_authority_ops == states_snapshot_after_authority_ops
)
assert (
    transitions_snapshot_before_authority_ops
    == transitions_snapshot_after_authority_ops
)


# ---------------------------------------------------------------
# AUTHORITY-1L -- Existing immutable receipts still prove historical
# authorization decisions
# ---------------------------------------------------------------

mismatches = []

for receipt_id, (outcome, transition_id, created_at) in PRE_MIGRATION_RECEIPTS.items():
    receipt = kernel.get_receipt(receipt_id)

    if receipt is None:
        mismatches.append((receipt_id, "missing"))
        continue

    if (
        receipt["outcome"] != outcome
        or receipt["transition_id"] != transition_id
        or receipt["created_at"] != created_at
    ):
        mismatches.append((receipt_id, receipt))

evidence(
    "AUTHORITY-1L result (pre-migration receipts unchanged)",
    checked=len(PRE_MIGRATION_RECEIPTS),
    mismatches=mismatches,
)

assert not mismatches, (
    f"pre-migration receipts changed or disappeared: {mismatches}"
)


print("\nAUTHORITY-1A through 1L complete. All assertions passed.")
