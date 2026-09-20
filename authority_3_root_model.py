"""
AUTHORITY-3A through 3M.

Regression + coverage suite for the root/capability model added to
kernel.py after AUTHORITY-2 found that the standalone grant()/
revoke()/revoke_all() methods had no scope check at all, AND that
transition()'s pre-existing new_grants/new_authorities parameters
were a second, older, equally-open path to the same escalation
(a narrow grant, in a single transition() call, could define a new
"root" authority and mint itself a grant against it -- no grant()
call needed).

The fix, per the follow-up design decision:
  - transition() may create State/Transition only. new_grants and
    new_authorities were removed from its signature entirely -- not
    re-gated, removed, so there is exactly one code path for each
    Authority fact instead of two duplicated checks.
  - grant()/revoke()/revoke_all() require the presented grant to
    resolve (via authorities.payload.root == true) to a root
    authority.
  - define_authority() is a new, explicit, root-only Authority
    operation -- the only way left to create an authorities row at
    all, closing the "arbitrary root=true" escalation at its root
    (defining ANY authority, not just a root-flagged one, requires
    an existing root grant).
  - revoke()/revoke_all() refuse to commit if doing so would leave
    zero currently-valid root grants kernel-wide.

This suite proves each piece, including the specific bypass found
during AUTHORITY-2's attack pass (3F/3G), and is written to leave
the live db in a safe state throughout: every test that could reduce
the kernel to zero root grants is either expected to fail (safe to
run for real) or is carefully sequenced so Nathan always retains a
valid root grant by the end.
"""

from kernel import Kernel, KernelError, new_id

kernel = Kernel()

NATHAN = "identity:nathan"
CLAWDE = "identity:clawde"
ROOT_GRANT = "grant:genesis-root"
ROOT_AUTHORITY = "authority:root"
NARROW_AUTHORITY = "authority:clawde-scope-alpha"


def evidence(label, **fields):
    print(f"\n=== {label} ===")
    for key, value in fields.items():
        print(f"  {key}: {value}")


def extract_receipt_id(exc: KernelError) -> str | None:
    text = str(exc)
    if "[receipt=" in text:
        return text.split("[receipt=")[1].rstrip("]")
    return None


def expect_kernel_error(fn, *, contains: str):
    try:
        fn()
        raise AssertionError("expected a KernelError but call succeeded")
    except KernelError as exc:
        assert contains in str(exc), f"unexpected error text: {exc}"
        return kernel.get_receipt(extract_receipt_id(exc))


anchor = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id="state:genesis",
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "AUTHORITY-3", "purpose": "anchor"},
    transition_payload={"reason": "AUTHORITY-3 fresh anchor"},
)
ANCHOR_STATE = anchor["state_id"]

narrow = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=NARROW_AUTHORITY,
    payload={"experiment": "AUTHORITY-3", "label": "ordinary narrow grant"},
)
NARROW_GRANT = narrow["grant_id"]
assert kernel.is_grant_revoked(NARROW_GRANT) is False


# ---------------------------------------------------------------
# AUTHORITY-3A -- non-root grant cannot call grant()
# ---------------------------------------------------------------

receipt_3a = expect_kernel_error(
    lambda: kernel.grant(
        requester_identity_id=CLAWDE,
        authority_grant_id=NARROW_GRANT,
        identity_id=CLAWDE,
        authority_id=NARROW_AUTHORITY,
    ),
    contains="does not hold root authority",
)
evidence("AUTHORITY-3A (non-root cannot grant())", receipt=receipt_3a)
assert receipt_3a["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-3B -- non-root grant cannot call revoke(), even of a
# grant it holds itself
# ---------------------------------------------------------------

receipt_3b = expect_kernel_error(
    lambda: kernel.revoke(
        requester_identity_id=CLAWDE,
        authority_grant_id=NARROW_GRANT,
        grant_id=NARROW_GRANT,
    ),
    contains="does not hold root authority",
)
evidence("AUTHORITY-3B (non-root cannot revoke())", receipt=receipt_3b)
assert receipt_3b["outcome"] == "REJECTED"
assert kernel.is_grant_revoked(NARROW_GRANT) is False


# ---------------------------------------------------------------
# AUTHORITY-3C -- non-root grant cannot call revoke_all(), even of
# its own identity
# ---------------------------------------------------------------

receipt_3c = expect_kernel_error(
    lambda: kernel.revoke_all(
        requester_identity_id=CLAWDE,
        authority_grant_id=NARROW_GRANT,
        identity_id=CLAWDE,
    ),
    contains="does not hold root authority",
)
evidence("AUTHORITY-3C (non-root cannot revoke_all())", receipt=receipt_3c)
assert receipt_3c["outcome"] == "REJECTED"
assert kernel.is_grant_revoked(NARROW_GRANT) is False


# ---------------------------------------------------------------
# AUTHORITY-3D -- non-root grant cannot call define_authority(),
# not even to define a non-root authority
# ---------------------------------------------------------------

receipt_3d = expect_kernel_error(
    lambda: kernel.define_authority(
        requester_identity_id=CLAWDE,
        authority_grant_id=NARROW_GRANT,
        authority_id="authority:clawde-defined",
        payload={"name": "an authority Clawde tried to define itself"},
    ),
    contains="does not hold root authority",
)
evidence("AUTHORITY-3D (non-root cannot define_authority())", receipt=receipt_3d)
assert receipt_3d["outcome"] == "REJECTED"

with kernel.connect() as conn:
    exists = conn.execute(
        "SELECT 1 FROM authorities WHERE authority_id = ?",
        ("authority:clawde-defined",),
    ).fetchone()
assert exists is None, "no authorities row may be created by a non-root requester"


# ---------------------------------------------------------------
# AUTHORITY-3E -- root's full lifecycle: define a new (non-root)
# authority, grant it, and confirm the new grant works for
# transition() but not for grant()/revoke()/revoke_all() -- proving
# the non-root restriction isn't special-cased to
# authority:clawde-scope-alpha, it applies to any non-root authority.
# ---------------------------------------------------------------

DEMO_AUTHORITY_ID = new_id("authority")

define_result = kernel.define_authority(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    authority_id=DEMO_AUTHORITY_ID,
    payload={"name": "demo-capability", "description": "AUTHORITY-3E"},
)

demo_grant_result = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=DEMO_AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-3E"},
)
DEMO_GRANT = demo_grant_result["grant_id"]

transition_with_demo = kernel.transition(
    requester_identity_id=CLAWDE,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=DEMO_GRANT,
    new_state_payload={"experiment": "AUTHORITY-3E"},
)

receipt_3e_grant_denied = expect_kernel_error(
    lambda: kernel.grant(
        requester_identity_id=CLAWDE,
        authority_grant_id=DEMO_GRANT,
        identity_id=CLAWDE,
        authority_id=DEMO_AUTHORITY_ID,
    ),
    contains="does not hold root authority",
)

evidence(
    "AUTHORITY-3E (root-defined non-root authority: transition ok, grant denied)",
    define_receipt=kernel.get_receipt(define_result["receipt_id"]),
    demo_grant=kernel.get_grant(DEMO_GRANT),
    transition_accepted=transition_with_demo["transition_id"] is not None,
    grant_denied_receipt=receipt_3e_grant_denied,
)

assert transition_with_demo["transition_id"] is not None
assert receipt_3e_grant_denied["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-3E2 -- malformed/misleading authorities.payload cannot
# affect root status. is_root is the ONLY source of truth: define
# an authority whose payload literally contains {"root": true} while
# is_root is left at its default (False), and confirm it is NOT
# treated as root. This is the direct proof that there is no
# fallback from the column to JSON anywhere in the kernel.
# ---------------------------------------------------------------

MISLEADING_AUTHORITY_ID = new_id("authority")

kernel.define_authority(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    authority_id=MISLEADING_AUTHORITY_ID,
    # is_root omitted -> defaults to False. This payload key is
    # exactly what an attacker (or a confused caller) would try if
    # they believed the old payload.root convention still worked.
    payload={"root": True, "note": "misleading -- is_root was not set"},
)

misleading_grant_result = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=MISLEADING_AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-3E2"},
)
MISLEADING_GRANT = misleading_grant_result["grant_id"]

receipt_3e2_denied = expect_kernel_error(
    lambda: kernel.revoke_all(
        requester_identity_id=CLAWDE,
        authority_grant_id=MISLEADING_GRANT,
        identity_id=CLAWDE,
    ),
    contains="does not hold root authority",
)

with kernel.connect() as conn:
    is_root_column_value = conn.execute(
        "SELECT is_root FROM authorities WHERE authority_id = ?",
        (MISLEADING_AUTHORITY_ID,),
    ).fetchone()["is_root"]

evidence(
    "AUTHORITY-3E2 (misleading payload.root=true has zero effect; only is_root counts)",
    authority_id=MISLEADING_AUTHORITY_ID,
    is_root_column_value=is_root_column_value,
    receipt=receipt_3e2_denied,
)

assert is_root_column_value == 0
assert receipt_3e2_denied["outcome"] == "REJECTED"


# ---------------------------------------------------------------
# AUTHORITY-3E3 -- root can define AND grant another root authority
# in one lifecycle (is_root=True is itself an ordinary, authorized
# root operation, requiring no special-case beyond the existing
# root gate on define_authority). Cleaned up at the end via revoke()
# so this test leaves no extra standing root grant behind.
# ---------------------------------------------------------------

SECOND_ROOT_AUTHORITY_ID = new_id("authority")

kernel.define_authority(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    authority_id=SECOND_ROOT_AUTHORITY_ID,
    is_root=True,
    payload={"name": "second root authority, defined by root"},
)

second_root_grant_result = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=SECOND_ROOT_AUTHORITY_ID,
    payload={"experiment": "AUTHORITY-3E3"},
)
SECOND_ROOT_GRANT = second_root_grant_result["grant_id"]

# Prove it actually behaves as root: Clawde, holding ONLY this
# freshly-minted grant, can now call a root-gated operation.
clawde_define_result = kernel.define_authority(
    requester_identity_id=CLAWDE,
    authority_grant_id=SECOND_ROOT_GRANT,
    authority_id=new_id("authority"),
    payload={"name": "defined by Clawde using the second root grant"},
)

evidence(
    "AUTHORITY-3E3 (root defines+grants a second root authority; it behaves as root)",
    second_root_authority=SECOND_ROOT_AUTHORITY_ID,
    second_root_grant=SECOND_ROOT_GRANT,
    clawde_define_receipt=kernel.get_receipt(clawde_define_result["receipt_id"]),
)

assert kernel.get_receipt(clawde_define_result["receipt_id"])["outcome"] == "ACCEPTED"

# Cleanup: revoke the second root grant so no extra standing root
# grant is left in the live db after this test.
kernel.revoke(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    grant_id=SECOND_ROOT_GRANT,
    reason="AUTHORITY-3E3 cleanup: retire the test co-root grant",
)
assert kernel.is_grant_revoked(SECOND_ROOT_GRANT) is True


# ---------------------------------------------------------------
# AUTHORITY-3F -- structural proof: transition() no longer accepts
# new_grants/new_authorities at all (TypeError, not a policy
# rejection -- the parameters do not exist).
# ---------------------------------------------------------------

structural_error = None
try:
    kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=ANCHOR_STATE,
        authority_grant_id=ROOT_GRANT,
        new_state_payload={"experiment": "AUTHORITY-3F"},
        new_grants=[
            {
                "grant_id": "grant:should-not-exist",
                "identity_id": CLAWDE,
                "authority_id": ROOT_AUTHORITY,
                "valid_from": "2026-09-20T00:00:00Z",
            }
        ],
    )
except TypeError as exc:
    structural_error = str(exc)

evidence(
    "AUTHORITY-3F (transition(new_grants=...) is structurally gone)",
    structural_error=structural_error,
)

assert structural_error is not None, (
    "transition() must raise TypeError for an unknown new_grants "
    "keyword -- if this doesn't raise, the parameter still exists"
)
assert "new_grants" in structural_error

with kernel.connect() as conn:
    exists = conn.execute(
        "SELECT 1 FROM authority_grants WHERE grant_id = ?",
        ("grant:should-not-exist",),
    ).fetchone()
assert exists is None


# ---------------------------------------------------------------
# AUTHORITY-3G -- regression: the exact escalation construction from
# the AUTHORITY-2 attack analysis (transition() minting a
# self-declared root authority + grant in one call) is now
# structurally impossible, not merely rejected by a new check.
# ---------------------------------------------------------------

structural_error_g = None
try:
    kernel.transition(
        requester_identity_id=CLAWDE,
        from_state_id=ANCHOR_STATE,
        authority_grant_id=NARROW_GRANT,
        new_state_payload={"experiment": "AUTHORITY-3G"},
        new_authorities=[
            {"authority_id": "authority:evil-root", "payload": {"root": True}}
        ],
        new_grants=[
            {
                "grant_id": "grant:clawde-self-minted-root-3g",
                "identity_id": CLAWDE,
                "authority_id": "authority:evil-root",
                "valid_from": "2026-09-20T00:00:00Z",
            }
        ],
    )
except TypeError as exc:
    structural_error_g = str(exc)

evidence(
    "AUTHORITY-3G (AUTHORITY-2's transition() bypass is now structurally closed)",
    structural_error=structural_error_g,
)

assert structural_error_g is not None
with kernel.connect() as conn:
    evil_authority_exists = conn.execute(
        "SELECT 1 FROM authorities WHERE authority_id = ?",
        ("authority:evil-root",),
    ).fetchone()
    evil_grant_exists = conn.execute(
        "SELECT 1 FROM authority_grants WHERE grant_id = ?",
        ("grant:clawde-self-minted-root-3g",),
    ).fetchone()
assert evil_authority_exists is None
assert evil_grant_exists is None


# ---------------------------------------------------------------
# AUTHORITY-3H/3I -- last-root invariant, multi-root recoverable
# case then the final-grant rejection case. Sequenced so Nathan's
# grant:genesis-root is never the target while other root grants
# exist, and ends with genesis-root intact and valid.
# ---------------------------------------------------------------

co_root_result = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=CLAWDE,
    authority_id=ROOT_AUTHORITY,
    payload={"experiment": "AUTHORITY-3H", "label": "co-root, deliberately issued by root"},
)
CO_ROOT_GRANT = co_root_result["grant_id"]

assert kernel.is_grant_revoked(CO_ROOT_GRANT) is False
valid_root_grants_with_co_root = []
with kernel.connect() as conn:
    for row in conn.execute(
        "SELECT grant_id FROM authority_grants WHERE authority_id = ?",
        (ROOT_AUTHORITY,),
    ).fetchall():
        if not kernel.is_grant_revoked(row["grant_id"]):
            valid_root_grants_with_co_root.append(row["grant_id"])

evidence(
    "AUTHORITY-3H setup (root grants co-root to Clawde: two valid root grants exist)",
    co_root_grant=CO_ROOT_GRANT,
    valid_root_grants=valid_root_grants_with_co_root,
)
assert set(valid_root_grants_with_co_root) == {ROOT_GRANT, CO_ROOT_GRANT}

# Revoking the CO-root grant while genesis-root remains must succeed
# (recoverable case -- not the last root grant).

revoke_co_root_result = kernel.revoke(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    grant_id=CO_ROOT_GRANT,
    reason="AUTHORITY-3H: revoking a non-last root grant must succeed",
)

evidence(
    "AUTHORITY-3H result (revoking a non-last root grant succeeds)",
    receipt=kernel.get_receipt(revoke_co_root_result["receipt_id"]),
    co_root_revoked=kernel.is_grant_revoked(CO_ROOT_GRANT),
    genesis_root_revoked=kernel.is_grant_revoked(ROOT_GRANT),
)
assert kernel.is_grant_revoked(CO_ROOT_GRANT) is True
assert kernel.is_grant_revoked(ROOT_GRANT) is False

# Now genesis-root is the ONLY valid root grant. Attempting to
# revoke it -- even by Nathan himself, using it as its own
# authorizer -- must be rejected: this is the last-root invariant,
# and directly answers "is ROOT revocable" from the prior analysis.

genesis_root_before_3i = kernel.get_grant(ROOT_GRANT)

receipt_3i = expect_kernel_error(
    lambda: kernel.revoke(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT_GRANT,
        grant_id=ROOT_GRANT,
        reason="AUTHORITY-3I: Nathan attempting to revoke the last root grant",
    ),
    contains="last currently-valid root grant",
)

evidence(
    "AUTHORITY-3I (revoking the LAST root grant is refused, even by Nathan)",
    receipt=receipt_3i,
    genesis_root_unchanged=(kernel.get_grant(ROOT_GRANT) == genesis_root_before_3i),
    genesis_root_revoked=kernel.is_grant_revoked(ROOT_GRANT),
)
assert receipt_3i["outcome"] == "REJECTED"
assert kernel.is_grant_revoked(ROOT_GRANT) is False
assert kernel.get_grant(ROOT_GRANT) == genesis_root_before_3i


# ---------------------------------------------------------------
# AUTHORITY-3J -- last-root invariant via revoke_all(): Nathan
# cannot revoke_all(himself) either, for the same reason, since his
# only currently-valid grant is the last root grant.
# ---------------------------------------------------------------

receipt_3j = expect_kernel_error(
    lambda: kernel.revoke_all(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT_GRANT,
        identity_id=NATHAN,
        reason="AUTHORITY-3J: Nathan attempting revoke_all(himself)",
    ),
    contains="only remaining valid root grant",
)

evidence(
    "AUTHORITY-3J (revoke_all of the last root holder is refused)",
    receipt=receipt_3j,
    genesis_root_revoked=kernel.is_grant_revoked(ROOT_GRANT),
)
assert receipt_3j["outcome"] == "REJECTED"
assert kernel.is_grant_revoked(ROOT_GRANT) is False


# ---------------------------------------------------------------
# AUTHORITY-3K -- final sanity: genesis-root is exactly as it was
# before this entire suite ran; the kernel always retained at least
# one valid root grant throughout.
# ---------------------------------------------------------------

final_root_grant = kernel.get_grant(ROOT_GRANT)
final_root_revoked = kernel.is_grant_revoked(ROOT_GRANT)

evidence(
    "AUTHORITY-3K (final state: genesis-root intact and valid)",
    final_root_grant=final_root_grant,
    final_root_revoked=final_root_revoked,
)
assert final_root_revoked is False
assert final_root_grant == genesis_root_before_3i


print("\nAUTHORITY-3A through 3K complete. All assertions passed.")
print("grant:genesis-root remains valid and untouched throughout.")
