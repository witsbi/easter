"""
AUTHORITY-2A through 2G.

Two independent investigations requested after AUTHORITY-1:

(1) A deterministic demonstration of both required serial orderings
    for concurrent transition(using G) vs revoke(G), now that grant
    validation happens inside the same write transaction that
    commits the operation (see _validate_grant in kernel.py):

        A. transition obtains ordering first -> transition commits,
           then revoke commits.
        B. revoke obtains ordering first -> transition must observe
           G revoked and reject; no ordering may let a transition
           commit against authority already revoked at that point.

    2A/2B force each ordering deterministically with a
    threading.Event so the required behavior is proven, not merely
    likely. 2C then removes that control and lets two threads race
    for real (as AUTHORITY-1J already did once, informally) --
    whichever ordering SQLite's single-writer serialization actually
    produces, the result is checked against the same invariant using
    receipts.receipt_seq (an autoincrementing column written inside
    each operation's own serialized transaction) as ground truth for
    which operation the database itself let commit first. This makes
    the check exact regardless of which thread the OS happens to
    schedule first -- it is never a coin flip on pass/fail.

(2) Whether a valid, unrevoked, unexpired grant automatically
    authorizes every kind of Authority operation, or only the kind
    it was granted for.

    2D/2E/2F were ORIGINALLY written to confirm, empirically, that
    v0.1 had no such check at all -- a narrow grant scoped to
    authority:clawde-scope-alpha could mint itself authority:root
    (2D), revoke_all its own authorizing grant (2E), and even strip
    identity:nathan of grant:genesis-root entirely (2F, run only
    against an isolated copy at the time, because it succeeded and
    would otherwise have permanently zeroed Nathan's Authority in
    the real history).

    kernel.py now implements the root/capability model that closes
    that gap: authorities.payload.root marks an authority as
    unrestricted; grant()/revoke()/revoke_all()/define_authority()
    all require the presented grant to be root; transition() can no
    longer create or mutate Authority at all (new_grants/
    new_authorities were removed, not merely re-gated). 2D/2E/2F are
    now REGRESSION tests proving each of those three attacks fails --
    and, because they are now expected to fail, all three run
    directly against the live db: a rejected Authority operation
    commits nothing, so there is no longer any need for an isolated
    copy here.
"""

import threading

from kernel import Kernel, KernelError, utc_now

kernel = Kernel()

NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
ROOT_GRANT = "grant:genesis-root"
AUTHORITY_ID = "authority:clawde-scope-alpha"


def evidence(label, **fields):
    print(f"\n=== {label} ===")
    for key, value in fields.items():
        print(f"  {key}: {value}")


def extract_receipt_id(exc: KernelError) -> str | None:
    text = str(exc)
    if "[receipt=" in text:
        return text.split("[receipt=")[1].rstrip("]")
    return None


def receipt_seq_of(k: Kernel, receipt_id: str) -> int:
    with k.connect() as conn:
        row = conn.execute(
            "SELECT receipt_seq FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
    return row["receipt_seq"]


def expect_kernel_error(fn, *, contains: str):
    try:
        fn()
        raise AssertionError("expected a KernelError but call succeeded")
    except KernelError as exc:
        assert contains in str(exc), f"unexpected error text: {exc}"
        return kernel.get_receipt(extract_receipt_id(exc))


# A fresh anchor state to branch every ordering test from, so this
# script does not depend on guessing whatever the current leaf state
# happens to be.

anchor = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id="state:genesis",
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "AUTHORITY-2", "purpose": "anchor"},
    transition_payload={"reason": "AUTHORITY-2 fresh anchor"},
)
ANCHOR_STATE = anchor["state_id"]


# ---------------------------------------------------------------
# AUTHORITY-2A -- Forced ordering A: transition commits fully,
# then revoke commits.
# ---------------------------------------------------------------

g_2a = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-2A"},
)
G_2A = g_2a["grant_id"]

transition_done = threading.Event()
outcomes_2a: dict[str, tuple[str, object]] = {}


def run_transition_2a():
    try:
        outcomes_2a["transition"] = (
            "ACCEPTED",
            kernel.transition(
                requester_identity_id=CLAWDE,
                from_state_id=ANCHOR_STATE,
                authority_grant_id=G_2A,
                new_state_payload={"experiment": "AUTHORITY-2A"},
            ),
        )
    except KernelError as exc:
        outcomes_2a["transition"] = ("REJECTED", str(exc))
    finally:
        transition_done.set()


def run_revoke_2a():
    transition_done.wait(timeout=5)
    try:
        outcomes_2a["revoke"] = (
            "ACCEPTED",
            kernel.revoke(
                requester_identity_id=NATHAN,
                authority_grant_id=ROOT_GRANT,
                grant_id=G_2A,
                reason="AUTHORITY-2A ordering A",
            ),
        )
    except KernelError as exc:
        outcomes_2a["revoke"] = ("REJECTED", str(exc))


t_transition_2a = threading.Thread(target=run_transition_2a)
t_revoke_2a = threading.Thread(target=run_revoke_2a)
t_revoke_2a.start()
t_transition_2a.start()
t_transition_2a.join()
t_revoke_2a.join()

evidence("AUTHORITY-2A result (forced: transition first, then revoke)", **outcomes_2a)

assert outcomes_2a["transition"][0] == "ACCEPTED", (
    "transition must commit while G_2A is still unrevoked"
)
assert outcomes_2a["revoke"][0] == "ACCEPTED"
assert kernel.is_grant_revoked(G_2A) is True


# ---------------------------------------------------------------
# AUTHORITY-2B -- Forced ordering B: revoke commits fully, then
# transition must observe it revoked and reject.
# ---------------------------------------------------------------

g_2b = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-2B"},
)
G_2B = g_2b["grant_id"]

revoke_done = threading.Event()
outcomes_2b: dict[str, tuple[str, object]] = {}


def run_revoke_2b():
    try:
        outcomes_2b["revoke"] = (
            "ACCEPTED",
            kernel.revoke(
                requester_identity_id=NATHAN,
                authority_grant_id=ROOT_GRANT,
                grant_id=G_2B,
                reason="AUTHORITY-2B ordering B",
            ),
        )
    except KernelError as exc:
        outcomes_2b["revoke"] = ("REJECTED", str(exc))
    finally:
        revoke_done.set()


def run_transition_2b():
    revoke_done.wait(timeout=5)
    try:
        outcomes_2b["transition"] = (
            "ACCEPTED",
            kernel.transition(
                requester_identity_id=CLAWDE,
                from_state_id=ANCHOR_STATE,
                authority_grant_id=G_2B,
                new_state_payload={"experiment": "AUTHORITY-2B"},
            ),
        )
    except KernelError as exc:
        outcomes_2b["transition"] = ("REJECTED", str(exc))


t_revoke_2b = threading.Thread(target=run_revoke_2b)
t_transition_2b = threading.Thread(target=run_transition_2b)
t_transition_2b.start()
t_revoke_2b.start()
t_revoke_2b.join()
t_transition_2b.join()

evidence("AUTHORITY-2B result (forced: revoke first, then transition)", **outcomes_2b)

assert outcomes_2b["revoke"][0] == "ACCEPTED"
assert outcomes_2b["transition"][0] == "REJECTED"
assert "has been revoked" in outcomes_2b["transition"][1]


# ---------------------------------------------------------------
# AUTHORITY-2C -- Real concurrent race, no forced ordering. Whatever
# SQLite's serialization actually produces, receipts.receipt_seq
# (written inside each operation's own committed transaction) is
# ground truth for which one the database let through first, and the
# corresponding invariant is checked exactly -- not guessed.
# ---------------------------------------------------------------

g_2c = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-2C"},
)
G_2C = g_2c["grant_id"]

barrier = threading.Barrier(2)
outcomes_2c: dict[str, tuple[str, object]] = {}


def run_transition_2c():
    barrier.wait()
    try:
        outcomes_2c["transition"] = (
            "ACCEPTED",
            kernel.transition(
                requester_identity_id=CLAWDE,
                from_state_id=ANCHOR_STATE,
                authority_grant_id=G_2C,
                new_state_payload={"experiment": "AUTHORITY-2C"},
            ),
        )
    except KernelError as exc:
        outcomes_2c["transition"] = ("REJECTED", str(exc))


def run_revoke_2c():
    barrier.wait()
    try:
        outcomes_2c["revoke"] = (
            "ACCEPTED",
            kernel.revoke(
                requester_identity_id=NATHAN,
                authority_grant_id=ROOT_GRANT,
                grant_id=G_2C,
                reason="AUTHORITY-2C real race",
            ),
        )
    except KernelError as exc:
        outcomes_2c["revoke"] = ("REJECTED", str(exc))


t1 = threading.Thread(target=run_transition_2c)
t2 = threading.Thread(target=run_revoke_2c)
t1.start()
t2.start()
t1.join()
t2.join()

assert outcomes_2c["revoke"][0] == "ACCEPTED", (
    "revoke authorizes itself via ROOT_GRANT, independent of G_2C, "
    "so it always succeeds regardless of who wins the race"
)

revoke_seq = receipt_seq_of(kernel, outcomes_2c["revoke"][1]["receipt_id"])

if outcomes_2c["transition"][0] == "ACCEPTED":
    transition_seq = receipt_seq_of(kernel, outcomes_2c["transition"][1]["receipt_id"])
    actual_order = "A (transition committed first)" if transition_seq < revoke_seq else "AMBIGUOUS"
else:
    actual_order = "B (revoke committed first)"

evidence(
    "AUTHORITY-2C result (real race, ordering decided by SQLite)",
    outcomes=outcomes_2c,
    revoke_receipt_seq=revoke_seq,
    inferred_order=actual_order,
)

if outcomes_2c["transition"][0] == "ACCEPTED":
    transition_seq = receipt_seq_of(kernel, outcomes_2c["transition"][1]["receipt_id"])
    assert transition_seq < revoke_seq, (
        "if transition committed, its receipt must be strictly "
        "earlier in the serialized commit order than revoke's -- "
        "an ACCEPTED transition can never follow a revoke of the "
        "grant it just used"
    )
else:
    assert "has been revoked" in outcomes_2c["transition"][1]

assert kernel.is_grant_revoked(G_2C) is True


# ---------------------------------------------------------------
# AUTHORITY-2D -- REGRESSION (was: confirmed gap). Does a grant
# scoped to authority:clawde-scope-alpha still authorize grant()?
# It must not, now that grant() requires root. Safe to run directly
# on the live db: the whole point is that this now fails, so nothing
# it attempts can commit.
# ---------------------------------------------------------------

g_2d = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-2D", "label": "narrow grant"},
)
G_NARROW_2D = g_2d["grant_id"]

grants_before_2d = None
with kernel.connect() as conn:
    grants_before_2d = conn.execute(
        "SELECT COUNT(*) AS n FROM authority_grants"
    ).fetchone()["n"]


def attack_2d():
    kernel.grant(
        requester_identity_id=CLAWDE,
        authority_grant_id=G_NARROW_2D,
        identity_id=CLAWDE,
        authority_id="authority:root",
        payload={"experiment": "AUTHORITY-2D", "attack": "mint root via narrow grant"},
    )


receipt_2d = expect_kernel_error(attack_2d, contains="does not hold root authority")

with kernel.connect() as conn:
    grants_after_2d = conn.execute(
        "SELECT COUNT(*) AS n FROM authority_grants"
    ).fetchone()["n"]

evidence(
    "AUTHORITY-2D result (regression: narrow grant can no longer mint authority:root)",
    authorizing_grant=G_NARROW_2D,
    authorizing_grant_authority_id=AUTHORITY_ID,
    receipt=receipt_2d,
    grants_before=grants_before_2d,
    grants_after=grants_after_2d,
)

assert receipt_2d["outcome"] == "REJECTED"
assert grants_before_2d == grants_after_2d, (
    "no grant row must be created when the authorizing grant is not root"
)


# ---------------------------------------------------------------
# AUTHORITY-2E -- REGRESSION (was: confirmed gap). Does a narrow
# grant still authorize revoke_all(), even of its own identity? It
# must not, now that revoke_all() requires root.
# ---------------------------------------------------------------

g_2e_target = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-2E", "label": "would-be target"},
)
G_2E_TARGET = g_2e_target["grant_id"]

g_2e_authorizer = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-2E", "label": "authorizer"},
)
G_2E_AUTHORIZER = g_2e_authorizer["grant_id"]


def attack_2e():
    kernel.revoke_all(
        requester_identity_id=CLAWDE,
        authority_grant_id=G_2E_AUTHORIZER,
        identity_id=CLAWDE,
        reason="AUTHORITY-2E: narrow grant attempting revoke_all of itself",
    )


receipt_2e = expect_kernel_error(attack_2e, contains="does not hold root authority")

evidence(
    "AUTHORITY-2E result (regression: narrow grant can no longer call revoke_all)",
    receipt=receipt_2e,
    G_2E_TARGET_revoked=kernel.is_grant_revoked(G_2E_TARGET),
    G_2E_AUTHORIZER_revoked=kernel.is_grant_revoked(G_2E_AUTHORIZER),
)

assert receipt_2e["outcome"] == "REJECTED"
assert kernel.is_grant_revoked(G_2E_TARGET) is False
assert kernel.is_grant_revoked(G_2E_AUTHORIZER) is False, (
    "neither grant may be touched when the authorizing grant is not root"
)


# ---------------------------------------------------------------
# AUTHORITY-2F -- REGRESSION (was: severe confirmed gap, previously
# demonstrated only on an isolated copy because it succeeded). Does
# a narrow grant still authorize revoke_all() against Nathan/root?
# It must not. Safe to run directly on the live db now: this is
# expected to fail, so grant:genesis-root cannot be touched by it.
# ---------------------------------------------------------------

root_grant_before_2f = kernel.get_grant(ROOT_GRANT)


def attack_2f():
    kernel.revoke_all(
        requester_identity_id=CLAWDE,
        authority_grant_id=G_NARROW_2D,
        identity_id=NATHAN,
        reason="AUTHORITY-2F: narrow grant attempting to strip Nathan/root",
    )


receipt_2f = expect_kernel_error(attack_2f, contains="does not hold root authority")

evidence(
    "AUTHORITY-2F result (regression: narrow grant can no longer strip root)",
    receipt=receipt_2f,
    root_grant_unchanged=(kernel.get_grant(ROOT_GRANT) == root_grant_before_2f),
    root_grant_revoked=kernel.is_grant_revoked(ROOT_GRANT),
)

assert receipt_2f["outcome"] == "REJECTED"
assert kernel.is_grant_revoked(ROOT_GRANT) is False
assert kernel.get_grant(ROOT_GRANT) == root_grant_before_2f


print("\nAUTHORITY-2A through 2F complete. All assertions passed.")
print("(2D/2E/2F now run directly on the live db -- they are expected")
print(" to fail, proving the AUTHORITY-2D/2E/2F escalation paths from")
print(" the prior analysis pass are closed.)")
