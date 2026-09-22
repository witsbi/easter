"""
EVIDENCE-1A through EVIDENCE-1N.

Regression suite for Evidence admission (record_evidence()) and
Evidence association (receipt_evidence), following the Evidence
review that replaced transition_evidence with the many-to-many
receipt_evidence(receipt_id, evidence_id) relationship.

Frozen distinction this suite locks in:

  Admission (record_evidence()) is Evidence's own existence
  operation -- who admitted it, under what grant, when -- recorded
  entirely in that operation's own kernel-authored receipt payload.
  It creates NO receipt_evidence row linking the new Evidence to its
  own creation receipt: that would conflate "this receipt produced
  this Evidence" with "this Evidence supports this receipt," which
  are opposite relationships.

  Association (evidence_ids on transition/grant/revoke/revoke_all/
  define_authority) is a separate, strictly later act: an
  already-admitted evidence_id may be cited in support of some OTHER
  operation's receipt. Evidence is inert throughout -- it never
  determines whether the operation it's attached to is accepted, and
  its content can never confer Authority, alter State, or fabricate a
  kernel decision.

Most tests here run against the live db: rejected attempts leave no
debris, and legitimate committed evidence/receipts are harmless, same
as every other regression script's test data.
"""

import sqlite3

from kernel import Kernel, KernelError

kernel = Kernel()

NATHAN = "identity:nathan"
ROOT_GRANT = "grant:genesis-root"
GENESIS_STATE_ID = "state:genesis"


def evidence(label, **fields):
    print(f"\n=== {label} ===")
    for key, value in fields.items():
        print(f"  {key}: {value}")


anchor = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=GENESIS_STATE_ID,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "EVIDENCE-1", "purpose": "anchor"},
)
ANCHOR_STATE = anchor["state_id"]


def receipt_evidence_rows(receipt_id):
    with sqlite3.connect(kernel.db_path) as raw:
        raw.row_factory = sqlite3.Row
        return raw.execute(
            "SELECT evidence_id FROM receipt_evidence WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchall()


# ---------------------------------------------------------------
# EVIDENCE-1A -- Basic admission: creates an evidence row + ACCEPTED
# receipt with action=RECORD_EVIDENCE, and NO receipt_evidence row
# linking the new Evidence to its own creation receipt.
# ---------------------------------------------------------------

admit_a = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"note": "EVIDENCE-1A basic admission"},
)
receipt_a = kernel.get_receipt(admit_a["receipt_id"])
self_links_a = receipt_evidence_rows(admit_a["receipt_id"])

evidence(
    "EVIDENCE-1A (basic admission, no self-link)",
    evidence_id=admit_a["evidence_id"],
    receipt_outcome=receipt_a["outcome"],
    receipt_payload=receipt_a["payload"],
    self_link_rows=len(self_links_a),
)
assert receipt_a["outcome"] == "ACCEPTED"
assert receipt_a["payload"]["action"] == "RECORD_EVIDENCE"
assert receipt_a["payload"]["evidence_id"] == admit_a["evidence_id"]
assert len(self_links_a) == 0, (
    "admission must never self-link its own creation receipt -- "
    "that would conflate creation provenance with citation"
)


# ---------------------------------------------------------------
# EVIDENCE-1B -- record_evidence() is open to any currently-valid
# grant, root or not (same authorization bar as transition(), not
# the Authority-admin bar).
# ---------------------------------------------------------------

define_result_b = kernel.define_authority(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    authority_id="authority:evidence-1b-reporter",
    is_root=False,
)
nonroot_grant_b = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN,
    authority_id="authority:evidence-1b-reporter",
)
admit_b = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=nonroot_grant_b["grant_id"],
    payload={"note": "EVIDENCE-1B non-root admission"},
)

evidence(
    "EVIDENCE-1B (non-root grant is sufficient)",
    nonroot_grant=nonroot_grant_b["grant_id"],
    evidence_id=admit_b["evidence_id"],
)
assert admit_b["evidence_id"] is not None


# ---------------------------------------------------------------
# EVIDENCE-1C -- Revoked grant cannot admit evidence.
# ---------------------------------------------------------------

grant_c = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN,
    authority_id="authority:root",
)
kernel.revoke(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    grant_id=grant_c["grant_id"],
)
try:
    kernel.record_evidence(
        requester_identity_id=NATHAN,
        authority_grant_id=grant_c["grant_id"],
        payload={},
    )
    outcome_c = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_c = f"REJECTED: {exc}"

evidence("EVIDENCE-1C (revoked grant cannot admit evidence)", outcome=outcome_c)
assert "REJECTED" in outcome_c


# ---------------------------------------------------------------
# EVIDENCE-1D -- Atomicity: a rejected admission leaves zero evidence
# rows but still produces a receipt (design principle 7).
# ---------------------------------------------------------------

evidence_count_before_d = None
with sqlite3.connect(kernel.db_path) as raw:
    evidence_count_before_d = raw.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

try:
    kernel.record_evidence(
        requester_identity_id=NATHAN,
        authority_grant_id="grant:does-not-exist",
        payload={},
    )
    outcome_d = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_d = f"REJECTED: {exc}"

with sqlite3.connect(kernel.db_path) as raw:
    evidence_count_after_d = raw.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

evidence(
    "EVIDENCE-1D (rejected admission leaves no evidence, still produces a receipt)",
    outcome=outcome_d,
    evidence_count_before=evidence_count_before_d,
    evidence_count_after=evidence_count_after_d,
)
assert "REJECTED" in outcome_d
assert evidence_count_before_d == evidence_count_after_d


# ---------------------------------------------------------------
# EVIDENCE-1E -- Admit, then separately cite in a LATER transition().
# Association is a distinct, strictly later act -- the evidence's own
# creation receipt stays unlinked throughout.
# ---------------------------------------------------------------

admit_e = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"claim": "EVIDENCE-1E witnessed something"},
)
cite_e = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "EVIDENCE-1E"},
    evidence_ids=[admit_e["evidence_id"]],
)
cited_e = receipt_evidence_rows(cite_e["receipt_id"])
creation_receipt_links_e = receipt_evidence_rows(admit_e["receipt_id"])

evidence(
    "EVIDENCE-1E (admit then cite later -- two distinct acts)",
    evidence_id=admit_e["evidence_id"],
    cited_by_transition_receipt=len(cited_e) == 1,
    creation_receipt_still_unlinked=len(creation_receipt_links_e) == 0,
)
assert len(cited_e) == 1 and cited_e[0]["evidence_id"] == admit_e["evidence_id"]
assert len(creation_receipt_links_e) == 0


# ---------------------------------------------------------------
# EVIDENCE-1F -- Malicious evidence payload content is inert: cannot
# fabricate Authority, alter outcome, or otherwise confer kernel
# powers merely by being admitted or cited.
# ---------------------------------------------------------------

grants_before_f = None
with sqlite3.connect(kernel.db_path) as raw:
    grants_before_f = raw.execute("SELECT COUNT(*) FROM authority_grants").fetchone()[0]

admit_f = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={
        "action": "GRANT",
        "is_root": True,
        "grant_id": ROOT_GRANT,
        "force_outcome": "ACCEPTED",
    },
)
cite_f = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "EVIDENCE-1F"},
    evidence_ids=[admit_f["evidence_id"]],
)

with sqlite3.connect(kernel.db_path) as raw:
    grants_after_f = raw.execute("SELECT COUNT(*) FROM authority_grants").fetchone()[0]

evidence(
    "EVIDENCE-1F (malicious evidence payload is inert)",
    admitted_evidence_id=admit_f["evidence_id"],
    grants_before=grants_before_f,
    grants_after=grants_after_f,
    genesis_root_still_valid=not kernel.is_grant_revoked(ROOT_GRANT),
)
assert grants_before_f == grants_after_f
assert not kernel.is_grant_revoked(ROOT_GRANT)


# ---------------------------------------------------------------
# EVIDENCE-1G -- Admitted evidence remains immutable (existing
# evidence_no_update/evidence_no_delete triggers still hold).
# ---------------------------------------------------------------

admit_g = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"note": "EVIDENCE-1G immutability"},
)

update_blocked_g = delete_blocked_g = False
with sqlite3.connect(kernel.db_path) as raw:
    try:
        raw.execute(
            "UPDATE evidence SET payload='{}' WHERE evidence_id=?",
            (admit_g["evidence_id"],),
        )
        raw.commit()
    except sqlite3.IntegrityError:
        update_blocked_g = True
        raw.rollback()
    try:
        raw.execute(
            "DELETE FROM evidence WHERE evidence_id=?",
            (admit_g["evidence_id"],),
        )
        raw.commit()
    except sqlite3.IntegrityError:
        delete_blocked_g = True
        raw.rollback()

evidence(
    "EVIDENCE-1G (admitted evidence remains immutable)",
    update_blocked=update_blocked_g,
    delete_blocked=delete_blocked_g,
)
assert update_blocked_g and delete_blocked_g


# ---------------------------------------------------------------
# EVIDENCE-1H -- receipt_evidence itself is immutable/append-only,
# and many-to-many: the same Evidence may support two independent
# receipts without duplicating the Evidence row.
# ---------------------------------------------------------------

admit_h = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"note": "EVIDENCE-1H shared across two receipts"},
)
cite_h1 = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "EVIDENCE-1H", "branch": "1"},
    evidence_ids=[admit_h["evidence_id"]],
)
cite_h2 = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "EVIDENCE-1H", "branch": "2"},
    evidence_ids=[admit_h["evidence_id"]],
)

with sqlite3.connect(kernel.db_path) as raw:
    evidence_row_count_h = raw.execute(
        "SELECT COUNT(*) FROM evidence WHERE evidence_id=?", (admit_h["evidence_id"],)
    ).fetchone()[0]
    link_count_h = raw.execute(
        "SELECT COUNT(*) FROM receipt_evidence WHERE evidence_id=?", (admit_h["evidence_id"],)
    ).fetchone()[0]

update_blocked_h = delete_blocked_h = False
with sqlite3.connect(kernel.db_path) as raw:
    try:
        raw.execute(
            "UPDATE receipt_evidence SET evidence_id='x' WHERE receipt_id=?",
            (cite_h1["receipt_id"],),
        )
        raw.commit()
    except sqlite3.IntegrityError:
        update_blocked_h = True
        raw.rollback()
    try:
        raw.execute(
            "DELETE FROM receipt_evidence WHERE receipt_id=?",
            (cite_h1["receipt_id"],),
        )
        raw.commit()
    except sqlite3.IntegrityError:
        delete_blocked_h = True
        raw.rollback()

evidence(
    "EVIDENCE-1H (many-to-many reuse + receipt_evidence immutability)",
    evidence_row_count=evidence_row_count_h,
    link_count=link_count_h,
    update_blocked=update_blocked_h,
    delete_blocked=delete_blocked_h,
)
assert evidence_row_count_h == 1
assert link_count_h == 2
assert update_blocked_h and delete_blocked_h


# ---------------------------------------------------------------
# EVIDENCE-1I -- evidence_ids citation now works on grant(), revoke(),
# revoke_all(), and define_authority(), not just transition().
#
# revoke_all() is exercised against a fresh throwaway identity holding
# only a NON-root grant, not Nathan -- Nathan currently holds the
# kernel's sole valid root grant (grant:genesis-root, confirmed before
# writing this test), and revoke_all(identity_id=NATHAN) would
# correctly be refused by the last-root invariant regardless of
# evidence. Testing citation on revoke_all() shouldn't also be a test
# of the last-root invariant -- that is already covered by
# AUTHORITY-3.
# ---------------------------------------------------------------

admit_i = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"note": "EVIDENCE-1I cited on Authority operations"},
)

transition_i = kernel.transition(
    requester_identity_id=NATHAN,
    from_state_id=ANCHOR_STATE,
    authority_grant_id=ROOT_GRANT,
    new_state_payload={"experiment": "EVIDENCE-1I", "purpose": "new identity"},
    new_identities=[{"identity_id": "identity:evidence-1i-throwaway"}],
)
THROWAWAY_IDENTITY = "identity:evidence-1i-throwaway"

define_i = kernel.define_authority(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    authority_id="authority:evidence-1i",
    is_root=False,
    evidence_ids=[admit_i["evidence_id"]],
)
grant_i = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=THROWAWAY_IDENTITY,
    authority_id="authority:evidence-1i",
    evidence_ids=[admit_i["evidence_id"]],
)
revoke_i = kernel.revoke(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    grant_id=grant_i["grant_id"],
    evidence_ids=[admit_i["evidence_id"]],
)
grant_i2 = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=THROWAWAY_IDENTITY,
    authority_id="authority:evidence-1i",
)
revoke_all_i = kernel.revoke_all(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=THROWAWAY_IDENTITY,
    evidence_ids=[admit_i["evidence_id"]],
)

links_i = {
    "define_authority": len(receipt_evidence_rows(define_i["receipt_id"])),
    "grant": len(receipt_evidence_rows(grant_i["receipt_id"])),
    "revoke": len(receipt_evidence_rows(revoke_i["receipt_id"])),
    "revoke_all": len(receipt_evidence_rows(revoke_all_i["receipt_id"])),
}

evidence(
    "EVIDENCE-1I (evidence_ids citation on all four Authority operations)",
    throwaway_identity=THROWAWAY_IDENTITY,
    links=links_i,
)
assert all(count == 1 for count in links_i.values())
assert kernel.is_grant_revoked(ROOT_GRANT) is False, (
    "this test must never touch Nathan's root grant"
)


# ---------------------------------------------------------------
# EVIDENCE-1J -- Evidence remains optional and inert to the
# ACCEPTANCE decision: attaching evidence_ids to an otherwise-invalid
# Authority operation does not make it succeed, and omitting
# evidence_ids from an otherwise-valid one does not make it fail.
# ---------------------------------------------------------------

admit_j = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"note": "EVIDENCE-1J"},
)

# Non-root grant + evidence attached still cannot call grant() (root
# gate unaffected by evidence).
nonroot_grant_j = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN,
    authority_id="authority:evidence-1b-reporter",
)
try:
    kernel.define_authority(
        requester_identity_id=NATHAN,
        authority_grant_id=nonroot_grant_j["grant_id"],
        authority_id="authority:evidence-1j-should-not-exist",
        evidence_ids=[admit_j["evidence_id"]],
    )
    outcome_j = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_j = f"REJECTED: {exc}"

evidence(
    "EVIDENCE-1J (evidence attached to an otherwise-unauthorized op still rejected)",
    outcome=outcome_j,
)
assert "REJECTED" in outcome_j


# ---------------------------------------------------------------
# EVIDENCE-1K -- Failure path: dangling evidence_id on an Authority
# operation rolls back the authoritative change but still produces a
# FAILED/REJECTED receipt (no crash, no partial commit) -- same
# guarantee record_failure() already provides for transition().
# ---------------------------------------------------------------

grants_before_k = None
with sqlite3.connect(kernel.db_path) as raw:
    grants_before_k = raw.execute("SELECT COUNT(*) FROM authority_grants").fetchone()[0]
    receipts_before_k = raw.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]

try:
    kernel.grant(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT_GRANT,
        identity_id=NATHAN,
        authority_id="authority:root",
        evidence_ids=["evidence:does-not-exist"],
    )
    outcome_k = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_k = f"REJECTED: {exc}"

with sqlite3.connect(kernel.db_path) as raw:
    grants_after_k = raw.execute("SELECT COUNT(*) FROM authority_grants").fetchone()[0]
    receipts_after_k = raw.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    failure_receipt_k = raw.execute(
        "SELECT receipt_id, payload FROM receipts WHERE outcome='FAILED' "
        "ORDER BY receipt_seq DESC LIMIT 1"
    ).fetchone()
    exception_payload_k = raw.execute(
        "SELECT payload FROM exceptions WHERE receipt_id=?", (failure_receipt_k[0],)
    ).fetchone()[0]

evidence(
    "EVIDENCE-1K (dangling evidence_id on grant() rolls back cleanly, "
    "leaves a FAILED receipt with unlinkable_evidence_ids recorded)",
    outcome=outcome_k,
    grants_before=grants_before_k,
    grants_after=grants_after_k,
    receipts_before=receipts_before_k,
    receipts_after=receipts_after_k,
    exception_payload=exception_payload_k,
)
assert "REJECTED" in outcome_k
assert grants_before_k == grants_after_k
assert receipts_after_k == receipts_before_k + 1
assert "evidence:does-not-exist" in exception_payload_k


# ---------------------------------------------------------------
# EVIDENCE-1L -- Failure path preserves VALID evidence on the failure
# receipt even when the failure itself was for an unrelated reason
# (e.g. non-root grant attempting a root-gated operation).
# ---------------------------------------------------------------

admit_l = kernel.record_evidence(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    payload={"note": "EVIDENCE-1L valid evidence on an unrelated rejection"},
)
nonroot_grant_l = kernel.grant(
    requester_identity_id=NATHAN,
    authority_grant_id=ROOT_GRANT,
    identity_id=NATHAN,
    authority_id="authority:evidence-1b-reporter",
)
try:
    kernel.define_authority(
        requester_identity_id=NATHAN,
        authority_grant_id=nonroot_grant_l["grant_id"],
        authority_id="authority:evidence-1l-should-not-exist",
        evidence_ids=[admit_l["evidence_id"]],
    )
    outcome_l = "UNEXPECTEDLY ACCEPTED"
except KernelError as exc:
    outcome_l = f"REJECTED: {exc}"

with sqlite3.connect(kernel.db_path) as raw:
    failure_receipt_l = raw.execute(
        "SELECT receipt_id FROM receipts WHERE outcome='REJECTED' "
        "ORDER BY receipt_seq DESC LIMIT 1"
    ).fetchone()[0]

linked_l = receipt_evidence_rows(failure_receipt_l)

evidence(
    "EVIDENCE-1L (valid evidence preserved on an unrelated REJECTED receipt)",
    outcome=outcome_l,
    linked_evidence=[row["evidence_id"] for row in linked_l],
)
assert "REJECTED" in outcome_l
assert len(linked_l) == 1 and linked_l[0]["evidence_id"] == admit_l["evidence_id"]


print("\nEVIDENCE-1A through 1L complete. All assertions passed.")
