"""
STATE-1A through STATE-1L.

Regression suite for the State red-team review, following the State
design freeze:

  "Duplicate accepted transitions are valid separate branches. The
  next transition chooses which branch to continue from. If userland
  cannot resolve the choice, escalate to Nathan/root. In a simple
  duplicate-retry case, either identical branch may be continued.
  The kernel does not need deduplication, canonical-head selection,
  or branch merging."

Most tests here run against the live db, because they are either
rejected attempts (leave no debris) or legitimate committed states
(harmless, same as every other experiment script's test states).

Both open findings from the review have since been decided:

  1. states.payload now has CHECK(json_valid(payload))
     (migrate_states_add_json_valid_check.sql). Valid JSON is a
     kernel representation invariant, not userland interpretation,
     so it is SQL-structurally enforced now, the same split already
     used for authorities.is_root. STATE-1F below runs on the live
     db and asserts REJECTION -- no debris, because it now fails
     before ever being written.

  2. The orphan-graft path (STATE-1K) is explicitly NOT being closed.
     Creating an orphan requires bypassing the kernel and writing
     directly to its private storage -- that is already a boundary
     violation, and the decision is not to add a lineage-reachability
     walk to every ordinary transition() call to defend against
     arbitrary corruption beneath the kernel boundary. STATE-1K
     therefore still runs on an isolated throwaway copy (the orphan
     row is permanent -- states are append-only -- and must never
     land in the live db), and its assertions document this as the
     accepted, intentional shape of the boundary, not as a bug.
"""

import shutil
import sqlite3

from kernel import Kernel, KernelError, encode_payload, new_id, utc_now

kernel = Kernel()

NATHAN = "identity:nathan"
ROOT_GRANT = "grant:genesis-root"
GENESIS_STATE_ID = "state:genesis"


def evidence(label, **fields):
    print(f"\n=== {label} ===")
    for key, value in fields.items():
        print(f"  {key}: {value}")


def counts():
    return kernel.count_states(), kernel.count_transitions()


anchor = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=GENESIS_STATE_ID,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "STATE-1", "purpose": "anchor"},
)
ANCHOR_STATE = anchor["state_id"]


# ---------------------------------------------------------------
# STATE-1A -- Replay/branching (frozen decision): two identical
# transition() calls from the same from_state_id both commit, as
# distinct, independently valid branches. No deduplication.
# ---------------------------------------------------------------

replay_args = dict(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "STATE-1A", "replay": True},
)
result_a1 = kernel.transition(**replay_args)
result_a2 = kernel.transition(**replay_args)

evidence(
    "STATE-1A (replayed identical transition -> two valid separate branches)",
    branch_1=result_a1["state_id"],
    branch_2=result_a2["state_id"],
)

assert result_a1["state_id"] != result_a2["state_id"]
assert result_a1["transition_id"] != result_a2["transition_id"]
assert kernel.get_state(result_a1["state_id"]) is not None
assert kernel.get_state(result_a2["state_id"]) is not None

# Both branches remain independently usable -- continuing from
# either one is equally legitimate; the kernel picks neither.
continue_from_1 = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=result_a1["state_id"],
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "STATE-1A", "continued_from": "branch_1"},
)
continue_from_2 = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=result_a2["state_id"],
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "STATE-1A", "continued_from": "branch_2"},
)
assert continue_from_1["transition_id"] is not None
assert continue_from_2["transition_id"] is not None


# ---------------------------------------------------------------
# STATE-1B -- At most one incoming transition per state
# (UNIQUE(to_state_id)), attempted via direct SQL.
# ---------------------------------------------------------------

raw = sqlite3.connect(kernel.db_path)
raw.execute("PRAGMA foreign_keys = ON")
try:
    raw.execute(
        """
        INSERT INTO transitions
            (transition_id, from_state_id, to_state_id, authority_grant_id, created_at, payload)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (new_id("transition"), GENESIS_STATE_ID, ANCHOR_STATE, ROOT_GRANT, utc_now(), "{}"),
    )
    raw.commit()
    outcome_b = "UNEXPECTEDLY ACCEPTED"
except Exception as exc:
    outcome_b = f"REJECTED: {exc}"
raw.close()

evidence("STATE-1B (second incoming transition to an existing state)", outcome=outcome_b)
assert "REJECTED" in outcome_b
assert "UNIQUE" in outcome_b


# ---------------------------------------------------------------
# STATE-1C -- Transition referencing a nonexistent state, attempted
# via direct SQL (FK) and via the kernel API (from_state_id).
# ---------------------------------------------------------------

raw = sqlite3.connect(kernel.db_path)
raw.execute("PRAGMA foreign_keys = ON")
try:
    raw.execute(
        """
        INSERT INTO transitions
            (transition_id, from_state_id, to_state_id, authority_grant_id, created_at, payload)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (new_id("transition"), GENESIS_STATE_ID, "state:does-not-exist-1c", ROOT_GRANT, utc_now(), "{}"),
    )
    raw.commit()
    outcome_c_sql = "UNEXPECTEDLY ACCEPTED"
except Exception as exc:
    outcome_c_sql = f"REJECTED: {exc}"
raw.close()

states_before_c, transitions_before_c = counts()
try:
    kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id="state:does-not-exist-1c",
        authority_grant_id=ROOT_GRANT,
        new_state_payload={"should": "never commit"},
    )
    outcome_c_api = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_c_api = f"REJECTED: {exc}"
states_after_c, transitions_after_c = counts()

evidence(
    "STATE-1C (transition referencing a nonexistent state)",
    direct_sql=outcome_c_sql,
    via_kernel_api=outcome_c_api,
)
assert "REJECTED" in outcome_c_sql and "FOREIGN KEY" in outcome_c_sql
assert "REJECTED" in outcome_c_api
assert (states_before_c, transitions_before_c) == (states_after_c, transitions_after_c)


# ---------------------------------------------------------------
# STATE-1D -- Mutation of committed state (payload or otherwise),
# attempted via direct SQL (trigger).
# ---------------------------------------------------------------

before_mutation = kernel.get_state(ANCHOR_STATE)
raw = sqlite3.connect(kernel.db_path)
try:
    raw.execute(
        "UPDATE states SET payload = ? WHERE state_id = ?",
        (encode_payload({"rewritten": True}), ANCHOR_STATE),
    )
    raw.commit()
    outcome_d = "UNEXPECTEDLY ACCEPTED"
except Exception as exc:
    outcome_d = f"REJECTED: {exc}"
raw.close()
after_mutation = kernel.get_state(ANCHOR_STATE)

evidence("STATE-1D (mutate committed state payload)", outcome=outcome_d)
assert "REJECTED" in outcome_d
assert "immutable" in outcome_d
assert before_mutation == after_mutation


# ---------------------------------------------------------------
# STATE-1E -- Deletion of committed state, attempted via direct SQL
# (trigger).
# ---------------------------------------------------------------

raw = sqlite3.connect(kernel.db_path)
try:
    raw.execute("DELETE FROM states WHERE state_id = ?", (ANCHOR_STATE,))
    raw.commit()
    outcome_e = "UNEXPECTEDLY ACCEPTED"
except Exception as exc:
    outcome_e = f"REJECTED: {exc}"
raw.close()

evidence("STATE-1E (delete committed state)", outcome=outcome_e)
assert "REJECTED" in outcome_e
assert "append-only" in outcome_e
assert kernel.get_state(ANCHOR_STATE) is not None


# ---------------------------------------------------------------
# STATE-1F -- Malformed/non-JSON payload via direct SQL. DECIDED:
# states.payload now has CHECK(json_valid(payload))
# (migrate_states_add_json_valid_check.sql). The insert is rejected
# at the persistence layer before it can ever be written, so this
# now runs directly on the live db -- a rejected attempt leaves no
# debris, unlike before this fix.
# ---------------------------------------------------------------

states_before_f, transitions_before_f = counts()
raw = sqlite3.connect(kernel.db_path)
try:
    raw.execute(
        "INSERT INTO states (state_id, created_at, payload) VALUES (?, ?, ?)",
        ("state:state-1f-malformed", utc_now(), "not json at all {{{"),
    )
    raw.commit()
    outcome_f_insert = "UNEXPECTEDLY ACCEPTED"
except Exception as exc:
    outcome_f_insert = f"REJECTED: {exc}"
raw.close()
states_after_f, transitions_after_f = counts()

evidence(
    "STATE-1F (malformed JSON payload -- rejected at persistence layer)",
    insert_outcome=outcome_f_insert,
)
assert "REJECTED" in outcome_f_insert
assert "CHECK constraint failed" in outcome_f_insert
assert (states_before_f, transitions_before_f) == (states_after_f, transitions_after_f)
assert kernel.get_state("state:state-1f-malformed") is None


# ---------------------------------------------------------------
# STATE-1G -- NaN/Infinity rejected via the current Kernel API,
# before ever reaching SQLite.
# ---------------------------------------------------------------

for label, value in [("nan", float("nan")), ("inf", float("inf")), ("-inf", float("-inf"))]:
    states_before_g, transitions_before_g = counts()
    try:
        kernel.transition(
            requester_identity_id=NATHAN,
            from_state_id=ANCHOR_STATE,
            authority_grant_id=ROOT_GRANT,
            new_state_payload={"value": value},
        )
        outcome_g = "UNEXPECTEDLY ACCEPTED"
    except KernelError as exc:
        outcome_g = f"REJECTED: {exc}"
    states_after_g, transitions_after_g = counts()

    evidence(f"STATE-1G ({label})", outcome=outcome_g)
    assert "REJECTED" in outcome_g
    assert (states_before_g, transitions_before_g) == (states_after_g, transitions_after_g)


# ---------------------------------------------------------------
# STATE-1H -- Failed authorization leaves no State/Transition debris.
# ---------------------------------------------------------------

states_before_h, transitions_before_h = counts()
try:
    kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=ANCHOR_STATE,
        authority_grant_id="grant:does-not-exist",
        new_state_payload={"should": "never commit"},
    )
    outcome_h = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_h = f"REJECTED: {exc}"
states_after_h, transitions_after_h = counts()

evidence("STATE-1H (failed authorization leaves no debris)", outcome=outcome_h)
assert "REJECTED" in outcome_h
assert (states_before_h, transitions_before_h) == (states_after_h, transitions_after_h)


# ---------------------------------------------------------------
# STATE-1I -- Bogus evidence_id rolls back the WHOLE transition
# (State + Transition), not just the evidence link.
# ---------------------------------------------------------------

states_before_i, transitions_before_i = counts()
try:
    kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=ANCHOR_STATE,
        authority_grant_id=ROOT_GRANT,
        new_state_payload={"should": "never commit"},
        evidence_ids=["evidence:does-not-exist"],
    )
    outcome_i = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_i = f"REJECTED: {exc}"
states_after_i, transitions_after_i = counts()

evidence("STATE-1I (bogus evidence_id rolls back the whole transition)", outcome=outcome_i)
assert "REJECTED" in outcome_i
assert (states_before_i, transitions_before_i) == (states_after_i, transitions_after_i)


# ---------------------------------------------------------------
# STATE-1J -- new_identities cannot hijack an existing identity_id.
# ---------------------------------------------------------------

nathan_before = None
with kernel.connect() as conn:
    nathan_before = conn.execute(
        "SELECT payload FROM identities WHERE identity_id = ?", (NATHAN,)
    ).fetchone()["payload"]

states_before_j, transitions_before_j = counts()
try:
    kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=ANCHOR_STATE,
        authority_grant_id=ROOT_GRANT,
        new_state_payload={"attack": "hijack existing identity"},
        new_identities=[{"identity_id": NATHAN, "payload": {"hijacked": True}}],
    )
    outcome_j = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_j = f"REJECTED: {exc}"
states_after_j, transitions_after_j = counts()

with kernel.connect() as conn:
    nathan_after = conn.execute(
        "SELECT payload FROM identities WHERE identity_id = ?", (NATHAN,)
    ).fetchone()["payload"]

evidence("STATE-1J (new_identities cannot hijack an existing identity)", outcome=outcome_j)
assert "REJECTED" in outcome_j
assert (states_before_j, transitions_before_j) == (states_after_j, transitions_after_j)
assert nathan_before == nathan_after


# ---------------------------------------------------------------
# STATE-1K -- Orphan state creation + grafting via legitimate
# transition(). DECIDED: this is explicitly accepted, not a bug.
# Creating the orphan requires bypassing the kernel and writing
# directly to its private storage -- already a boundary violation --
# and the decision is not to add a lineage-reachability walk to
# every ordinary transition() call to defend against arbitrary
# corruption beneath that boundary. This test is regression evidence
# of that accepted boundary, not a pending finding: if this ever
# starts failing, the boundary's shape has changed and that itself
# needs reporting, not silent adaptation.
#
# Runs on an ISOLATED COPY regardless: an orphan inserted via direct
# SQL is permanent (append-only) and must never land in the live db.
# ---------------------------------------------------------------

ORPHAN_ID = "state:state-1k-orphan"
ISOLATED_DB = "/tmp/state_redteam_isolated.db"
shutil.copyfile(kernel.db_path, ISOLATED_DB)
isolated_kernel = Kernel(db_path=ISOLATED_DB)

raw = sqlite3.connect(ISOLATED_DB)
raw.execute("PRAGMA foreign_keys = ON")
raw.execute(
    "INSERT INTO states (state_id, created_at, payload) VALUES (?, ?, ?)",
    (ORPHAN_ID, utc_now(), encode_payload({"note": "direct-SQL orphan, no transition"})),
)
raw.commit()
raw.close()

with isolated_kernel.connect() as conn:
    incoming_to_orphan = conn.execute(
        "SELECT COUNT(*) AS n FROM transitions WHERE to_state_id = ?", (ORPHAN_ID,)
    ).fetchone()["n"]

graft_result = isolated_kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ORPHAN_ID,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"note": "grafted onto an illegitimate orphan root"},
)

evidence(
    "STATE-1K (orphan creation + graft -- accepted boundary, isolated copy)",
    ran_against=ISOLATED_DB,
    live_db_touched=False,
    orphan_incoming_transitions=incoming_to_orphan,
    graft_accepted=graft_result["transition_id"] is not None,
)

assert incoming_to_orphan == 0, "orphan has no incoming transition, by construction"
assert graft_result["transition_id"] is not None, (
    "ACCEPTED BOUNDARY, by decision: transition() extends from an "
    "orphan with no reachability check -- from_state_id validation "
    "is existence-only. Defending against this would mean adding a "
    "lineage walk to every ordinary transition() to guard against "
    "corruption that already required bypassing the kernel; that "
    "was explicitly declined. If this assertion ever fails, the "
    "boundary's shape changed and needs reporting, not silent fixing."
)


# ---------------------------------------------------------------
# STATE-1L -- State payload claiming authority/root status has zero
# effect on any Authority check.
# ---------------------------------------------------------------

sneaky = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={
        "is_root": True,
        "authority_id": "authority:root",
        "grant_id": ROOT_GRANT,
    },
)

evidence(
    "STATE-1L (state payload claiming authority has zero effect)",
    committed_state=sneaky["state_id"],
)
assert sneaky["transition_id"] is not None
# No kernel code path reads states.payload for authority purposes --
# confirmed by inspection (grep) of kernel.py's root/capability model.
# This test locks in that the state still commits as ordinary,
# authority-inert userland content.


print("\nSTATE-1A through 1L complete. All assertions passed.")
print(f"STATE-1K ran only against {ISOLATED_DB}, never the live database.")
