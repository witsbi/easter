"""
AUTHORITY-0B through 0F. RETIRED / HISTORICAL -- do not run.

Continues the authority lifecycle experiment from AUTHORITY-0A
(authority_0a.py), which established identity:clawde through a
Nathan/root-authorized state transition. Clawde had identity but no
authority at the end of 0A.

This script exercised: grant, exercise, exceed, revoke/supersede, and
post-revocation retry via `transition(supersedes_grant_ids=...)` and
`Kernel.is_grant_superseded`.

That mechanism coupled Authority revocation to State transitions --
revoking a grant required fabricating an unrelated state change just
to carry the fact. It has been removed. Revocation is now a
standalone kernel Authority operation (`Kernel.revoke`/`revoke_all`,
read back via `Kernel.is_grant_revoked`) that requires no State
transition at all. See authority_1_standalone.py for the superseding
experiment (AUTHORITY-1A..1L) that exercises the new model.

This script is kept only as a provenance record of what v0.1's first
revocation attempt looked like -- it will now raise a TypeError if
run, since `transition()` no longer accepts `supersedes_grant_ids`
and `Kernel.is_grant_superseded` no longer exists. Do not "fix" it to
run again; the point of AUTHORITY-1 is that this approach was
deliberately replaced, not merely renamed.
"""

from kernel import Kernel, KernelError, utc_now

kernel = Kernel()

# State produced by AUTHORITY-0A in the current baseline database,
# verified below via kernel.get_state() rather than trusted blindly.
ANCHOR_STATE_ID = "state:b4d2fbd8-837d-4bdc-a640-2a02cdce4604"

NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
ROOT_GRANT = "grant:genesis-root"

NARROW_AUTHORITY_ID = "authority:clawde-scope-alpha"
NARROW_GRANT_ID = "grant:clawde-alpha"


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


anchor = kernel.get_state(ANCHOR_STATE_ID)
assert anchor is not None, (
    "AUTHORITY-0A anchor state not found -- run authority_0a.py "
    "against this database first"
)
evidence(
    "Anchor (AUTHORITY-0A result, verified via kernel.get_state)",
    state_id=ANCHOR_STATE_ID,
    payload=anchor["payload"],
)


# ---------------------------------------------------------------
# AUTHORITY-0B -- Grant
# ---------------------------------------------------------------
# Nathan/root causes an authoritative transition that creates a
# deliberately narrow authority and grants it to identity:clawde.
# new_authorities / new_grants write into the existing `authorities`
# and `authority_grants` tables only -- no schema change.

result_0b = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE_ID,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={
        "experiment": "AUTHORITY-0B",
        "event": "authority granted",
        "identity_id": CLAWDE,
        "authority_id": NARROW_AUTHORITY_ID,
        "grant_id": NARROW_GRANT_ID,
    },
    transition_payload={
        "experiment": "AUTHORITY-0B",
        "reason": (
            "Nathan/root grants a deliberately narrow authority to "
            "identity:clawde"
        ),
    },
    new_authorities=[
        {
            "authority_id": NARROW_AUTHORITY_ID,
            "payload": {
                "name": "clawde-scope-alpha",
                "description": (
                    "Narrow authority for the AUTHORITY-0 experiment "
                    "lineage. This description is opaque userland "
                    "text -- v0.1 does not parse or enforce it."
                ),
            },
        }
    ],
    new_grants=[
        {
            "grant_id": NARROW_GRANT_ID,
            "identity_id": CLAWDE,
            "authority_id": NARROW_AUTHORITY_ID,
            "valid_from": utc_now(),
            "payload": {
                "reason": "AUTHORITY-0B narrow grant to identity:clawde",
            },
        }
    ],
)

grant_0b = kernel.get_grant(NARROW_GRANT_ID)
receipt_0b = kernel.get_receipt(result_0b["receipt_id"])

evidence(
    "AUTHORITY-0B result (Grant)",
    requester_identity=NATHAN,
    authority_grant_exercised=ROOT_GRANT,
    source_state=ANCHOR_STATE_ID,
    resulting_state=result_0b["state_id"],
    transition_id=result_0b["transition_id"],
    receipt=receipt_0b,
    new_grant_row=grant_0b,
    new_grant_granted_by=grant_0b["granted_by_identity_id"],
)

assert grant_0b["granted_by_identity_id"] == NATHAN
assert grant_0b["identity_id"] == CLAWDE

STATE_AFTER_0B = result_0b["state_id"]


# ---------------------------------------------------------------
# AUTHORITY-0C -- Exercise
# ---------------------------------------------------------------
# Clawde requests/causes a transition using the grant it now holds.
# The kernel verifies requester_identity_id against the grant's
# recorded identity_id before allowing this to proceed.

result_0c = kernel.transition(
    requester_identity_id=CLAWDE,
    from_state_id=STATE_AFTER_0B,
    authority_grant_id=NARROW_GRANT_ID,
    new_state_payload={
        "experiment": "AUTHORITY-0C",
        "event": "clawde exercised its narrow grant",
    },
    transition_payload={
        "experiment": "AUTHORITY-0C",
        "reason": "Clawde exercises grant:clawde-alpha",
    },
)

receipt_0c = kernel.get_receipt(result_0c["receipt_id"])

evidence(
    "AUTHORITY-0C result (Exercise)",
    requester_identity=CLAWDE,
    authority_grant_exercised=NARROW_GRANT_ID,
    source_state=STATE_AFTER_0B,
    resulting_state=result_0c["state_id"],
    transition_id=result_0c["transition_id"],
    receipt=receipt_0c,
)

STATE_AFTER_0C = result_0c["state_id"]


# ---------------------------------------------------------------
# AUTHORITY-0D -- Exceed
# ---------------------------------------------------------------
# Clawde attempts to use a grant it does not hold: Nathan's root
# grant. v0.1's AUTHORITY primitive currently enforces possession
# (identity binding), temporal validity, and non-supersession -- it
# has no concept of an action's "scope" versus a grant's semantic
# label. The only kind of "exceeding authority" the kernel can
# currently detect is presenting a grant the requester does not
# hold. See the final report for the scope-enforcement gap this
# exposes (unchanged from the prior attempt -- it is not a schema
# question at all, so freezing schema.sql does not affect it).

states_before_0d, transitions_before_0d = counts()

outcome_0d = None
receipt_id_0d = None
try:
    kernel.transition(
        requester_identity_id=CLAWDE,
        from_state_id=STATE_AFTER_0C,
        authority_grant_id=ROOT_GRANT,  # Clawde does not hold this
        new_state_payload={
            "experiment": "AUTHORITY-0D",
            "event": "clawde attempted to use root authority",
        },
        transition_payload={
            "experiment": "AUTHORITY-0D",
            "reason": "Clawde attempts to exceed its authority",
        },
    )
    outcome_0d = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_0d = str(exc)
    receipt_id_0d = extract_receipt_id(exc)

states_after_0d, transitions_after_0d = counts()
receipt_0d = kernel.get_receipt(receipt_id_0d) if receipt_id_0d else None

evidence(
    "AUTHORITY-0D result (Exceed)",
    requester_identity=CLAWDE,
    authority_grant_attempted=ROOT_GRANT,
    source_state=STATE_AFTER_0C,
    outcome=outcome_0d,
    receipt=receipt_0d,
    states_before=states_before_0d,
    states_after=states_after_0d,
    transitions_before=transitions_before_0d,
    transitions_after=transitions_after_0d,
    unauthorized_state_leakage=(states_after_0d != states_before_0d),
    unauthorized_transition_leakage=(
        transitions_after_0d != transitions_before_0d
    ),
)

assert states_after_0d == states_before_0d
assert transitions_after_0d == transitions_before_0d
assert receipt_0d is not None and receipt_0d["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-0E -- Revoke/supersede
# ---------------------------------------------------------------
# Nathan/root causes an authorized forward-only transition that
# supersedes Clawde's effective authority. The historical grant row
# is never mutated or deleted -- supersession is recorded as a
# reserved key ("supersedes_grant_ids") inside this NEW transition's
# own payload column, which already exists and is already opaque to
# SQLite. No new table, column, index, or trigger.

grant_before_revocation = kernel.get_grant(NARROW_GRANT_ID)
superseded_before = kernel.is_grant_superseded(NARROW_GRANT_ID)

result_0e = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=STATE_AFTER_0C,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={
        "experiment": "AUTHORITY-0E",
        "event": "clawde's narrow grant superseded",
        "superseded_grant_id": NARROW_GRANT_ID,
    },
    transition_payload={
        "experiment": "AUTHORITY-0E",
        "reason": "Nathan/root revokes Clawde's narrow authority",
    },
    supersedes_grant_ids=[NARROW_GRANT_ID],
)

grant_after_revocation = kernel.get_grant(NARROW_GRANT_ID)
superseded_after = kernel.is_grant_superseded(NARROW_GRANT_ID)
receipt_0e = kernel.get_receipt(result_0e["receipt_id"])
transition_0e_payload = receipt_0e["payload"]

evidence(
    "AUTHORITY-0E result (Revoke/supersede)",
    requester_identity=NATHAN,
    authority_grant_exercised=ROOT_GRANT,
    source_state=STATE_AFTER_0C,
    resulting_state=result_0e["state_id"],
    transition_id=result_0e["transition_id"],
    receipt=receipt_0e,
    grant_row_before=grant_before_revocation,
    grant_row_after=grant_after_revocation,
    grant_row_unchanged=(grant_before_revocation == grant_after_revocation),
    superseded_before=superseded_before,
    superseded_after=superseded_after,
)

assert grant_before_revocation == grant_after_revocation
assert superseded_before is False
assert superseded_after is True

STATE_AFTER_0E = result_0e["state_id"]


# ---------------------------------------------------------------
# AUTHORITY-0F -- Post-revocation exercise
# ---------------------------------------------------------------
# Clawde retries the exact operation that succeeded in 0C, presenting
# the same, now-superseded grant.

states_before_0f, transitions_before_0f = counts()

outcome_0f = None
receipt_id_0f = None
try:
    kernel.transition(
        requester_identity_id=CLAWDE,
        from_state_id=STATE_AFTER_0E,
        authority_grant_id=NARROW_GRANT_ID,
        new_state_payload={
            "experiment": "AUTHORITY-0F",
            "event": "clawde retried after revocation",
        },
        transition_payload={
            "experiment": "AUTHORITY-0F",
            "reason": "Clawde retries the previously permitted operation",
        },
    )
    outcome_0f = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_0f = str(exc)
    receipt_id_0f = extract_receipt_id(exc)

states_after_0f, transitions_after_0f = counts()
receipt_0f = kernel.get_receipt(receipt_id_0f) if receipt_id_0f else None

evidence(
    "AUTHORITY-0F result (Post-revocation exercise)",
    requester_identity=CLAWDE,
    authority_grant_attempted=NARROW_GRANT_ID,
    source_state=STATE_AFTER_0E,
    outcome=outcome_0f,
    receipt=receipt_0f,
    states_before=states_before_0f,
    states_after=states_after_0f,
    transitions_before=transitions_before_0f,
    transitions_after=transitions_after_0f,
    unauthorized_state_leakage=(states_after_0f != states_before_0f),
    unauthorized_transition_leakage=(
        transitions_after_0f != transitions_before_0f
    ),
)

assert states_after_0f == states_before_0f
assert transitions_after_0f == transitions_before_0f
assert receipt_0f is not None and receipt_0f["outcome"] == "REJECTED"

print("\nAUTHORITY-0B through 0F complete. All assertions passed.")
print("No schema.sql or genesis_seed.sql changes were required.")
