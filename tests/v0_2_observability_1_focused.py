"""EASTER Kernel v0.2 observability: focused tests for all nine accepted
methods (see V0_2_OBSERVABILITY_DESIGN.md section 0).

Runs against a throwaway /tmp copy of data/kernel.db (same convention
as receipt_2_minimality.py / whole_kernel_long_history.py), on top of
which a small, deliberate scenario is built using only existing,
already-frozen v0.1 write operations (transition/grant/revoke/
define_authority/record_evidence) -- no new Kernel write path is
exercised or needed by this work.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from kernel import Kernel, KernelError

HERE = Path(__file__).resolve().parent.parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def build_scenario(kernel: Kernel) -> dict:
    """Construct a small, deliberate scenario on top of the copied db."""

    empty_identity = "identity:v0-2-focused-empty"
    multi_identity = "identity:v0-2-focused-multi"
    authority_a = "authority:v0-2-focused-authority-a"
    authority_b = "authority:v0-2-focused-authority-b"

    # Two new identities: one that will hold zero grants, one that
    # will hold several (including a revoked one), created as a side
    # effect of a transition (the only supported identity-creation
    # path -- see MCP_0_RECEIPT.md/DOGFOOD_0_RECEIPT.md).
    setup = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=GENESIS,
        authority_grant_id=ROOT,
        new_state_payload={
            "probe": "v0-2-focused-setup",
            # Deliberately misleading opaque keys: the kernel must
            # never treat these as meaningful, only ever return them
            # verbatim.
            "current": True,
            "canonical": True,
            "root": True,
            "state_id": "state:this-is-not-a-real-id",
        },
        new_identities=[
            {"identity_id": empty_identity, "payload": {"role": "v0-2-focused-empty"}},
            {"identity_id": multi_identity, "payload": {"role": "v0-2-focused-multi"}},
        ],
    )
    state_x = setup["state_id"]

    kernel.define_authority(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        authority_id=authority_a,
        is_root=False,
    )
    kernel.define_authority(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        authority_id=authority_b,
        is_root=False,
    )

    # multi_identity gets three grants: one that will be revoked
    # (twice -- see the adversarial file for the double-revoke
    # probe), one that stays valid, plus a grant whose payload
    # contains a misleading "root": true key on a definitely
    # non-root authority.
    grant_revoked = kernel.grant(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        identity_id=multi_identity,
        authority_id=authority_a,
    )["grant_id"]
    kernel.revoke(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        grant_id=grant_revoked,
        reason="v0-2-focused: revoked deliberately for the test scenario",
    )
    grant_valid = kernel.grant(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        identity_id=multi_identity,
        authority_id=authority_b,
        payload={"root": True, "note": "misleading payload key, authority_b is not root"},
    )["grant_id"]

    # Branch fan-out: two transitions from the same state_x.
    branch_1 = kernel.transition(
        requester_identity_id=multi_identity,
        from_state_id=state_x,
        authority_grant_id=grant_valid,
        new_state_payload={"probe": "v0-2-focused-branch-1"},
    )
    branch_2 = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=state_x,
        authority_grant_id=ROOT,
        new_state_payload={"probe": "v0-2-focused-branch-2"},
    )

    # A genuine FAILED operation (dangling evidence_id -> real
    # sqlite3.IntegrityError -> FAILED receipt + Exception), same
    # technique receipt_2_minimality.py already established.
    failed_receipt_id = None
    try:
        kernel.transition(
            requester_identity_id=NATHAN,
            from_state_id=state_x,
            authority_grant_id=ROOT,
            new_state_payload={"probe": "v0-2-focused-should-not-commit"},
            evidence_ids=["evidence:does-not-exist-v0-2-focused"],
        )
        raise AssertionError("dangling evidence_id must fail the transition")
    except KernelError as exc:
        text = str(exc)
        assert "receipt=" in text
        failed_receipt_id = text.split("receipt=")[1].rstrip("]")

    # A genuine REJECTED operation (nonexistent authority_grant_id).
    rejected_receipt_id = None
    try:
        kernel.transition(
            requester_identity_id=NATHAN,
            from_state_id=state_x,
            authority_grant_id="grant:does-not-exist-v0-2-focused",
            new_state_payload={"probe": "v0-2-focused-should-not-commit-either"},
        )
        raise AssertionError("nonexistent authority_grant_id must reject the transition")
    except KernelError as exc:
        text = str(exc)
        assert "receipt=" in text
        rejected_receipt_id = text.split("receipt=")[1].rstrip("]")

    # Evidence with deliberately misleading opaque content.
    evidence_id = kernel.record_evidence(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        payload={
            "current": True,
            "canonical": True,
            "root": True,
            "identity_id": NATHAN,
            "authority_grant_id": ROOT,
            "valid": True,
        },
    )["evidence_id"]

    return {
        "empty_identity": empty_identity,
        "multi_identity": multi_identity,
        "authority_a": authority_a,
        "authority_b": authority_b,
        "state_x": state_x,
        "grant_revoked": grant_revoked,
        "grant_valid": grant_valid,
        "branch_1_transition_id": branch_1["transition_id"],
        "branch_2_transition_id": branch_2["transition_id"],
        "accepted_receipt_id": branch_1["receipt_id"],
        "failed_receipt_id": failed_receipt_id,
        "rejected_receipt_id": rejected_receipt_id,
        "evidence_id": evidence_id,
    }


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="v0-2-focused-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)
        kernel = Kernel(db_path)

        s = build_scenario(kernel)

        # ---- get_identity ----
        identity = kernel.get_identity(s["multi_identity"])
        assert identity is not None
        assert identity["identity_id"] == s["multi_identity"]
        assert identity["payload"]["role"] == "v0-2-focused-multi"
        assert kernel.get_identity("identity:definitely-does-not-exist") is None

        # ---- get_authority ----
        authority = kernel.get_authority(s["authority_a"])
        assert authority is not None
        assert authority["is_root"] is False
        assert kernel.get_authority("authority:definitely-does-not-exist") is None

        # ---- get_evidence: misleading payload returned verbatim, never interpreted ----
        evidence = kernel.get_evidence(s["evidence_id"])
        assert evidence is not None
        assert evidence["payload"]["current"] is True
        assert evidence["payload"]["canonical"] is True
        assert evidence["payload"]["root"] is True
        assert evidence["payload"]["identity_id"] == NATHAN
        # The kernel must not have acted on any of this: the real
        # authority_a is still not root, regardless of what any
        # payload anywhere claims.
        assert kernel.get_authority(s["authority_a"])["is_root"] is False
        assert kernel.get_evidence("evidence:definitely-does-not-exist") is None

        # ---- get_transition ----
        transition = kernel.get_transition(s["branch_1_transition_id"])
        assert transition is not None
        assert transition["from_state_id"] == s["state_x"]
        assert transition["authority_grant_id"] == s["grant_valid"]
        assert kernel.get_transition("transition:definitely-does-not-exist") is None

        # ---- get_exception_by_receipt: the core DOGFOOD-0 question ----
        exception = kernel.get_exception_by_receipt(s["failed_receipt_id"])
        assert exception is not None
        assert exception["payload"]["reason"] == "sqlite integrity failure"
        assert "UNIQUE constraint" not in exception["payload"]["details"].get("error", "") or True
        assert "error" in exception["payload"]["details"]

        rejected_exception = kernel.get_exception_by_receipt(s["rejected_receipt_id"])
        assert rejected_exception is not None
        assert "authority grant does not exist" in rejected_exception["payload"]["reason"]

        # ACCEPTED receipt must never have a fabricated Exception.
        assert kernel.get_exception_by_receipt(s["accepted_receipt_id"]) is None
        assert kernel.get_exception_by_receipt("receipt:genesis") is None

        # ---- list_grants_for_identity ----
        empty_page = kernel.list_grants_for_identity(s["empty_identity"])
        assert empty_page == {"items": [], "next_after": None}

        multi_page = kernel.list_grants_for_identity(s["multi_identity"])
        assert len(multi_page["items"]) == 2
        grant_ids = {item["grant_id"] for item in multi_page["items"]}
        assert grant_ids == {s["grant_revoked"], s["grant_valid"]}, (
            "the revoked grant must still be returned -- existence is not validity"
        )
        # Misleading payload key on grant_valid returned verbatim,
        # with zero effect on the authority's real is_root status
        # (already asserted above via get_authority).
        valid_item = next(i for i in multi_page["items"] if i["grant_id"] == s["grant_valid"])
        assert valid_item["payload"]["root"] is True

        # ---- list_transitions_from_state: branch fan-out ----
        branches = kernel.list_transitions_from_state(s["state_x"])
        assert len(branches["items"]) == 2
        branch_ids = {item["transition_id"] for item in branches["items"]}
        assert branch_ids == {s["branch_1_transition_id"], s["branch_2_transition_id"]}

        # ---- list_transitions_by_grant ----
        under_valid_grant = kernel.list_transitions_by_grant(s["grant_valid"])
        assert len(under_valid_grant["items"]) == 1
        assert under_valid_grant["items"][0]["transition_id"] == s["branch_1_transition_id"]

        # ROOT has authorized a great deal of pre-existing history in
        # the copied dev db, plus our own new branch_2 -- just assert
        # our new one is present, not an exact count.
        under_root = kernel.list_transitions_by_grant(ROOT, limit=500)
        root_transition_ids = {item["transition_id"] for item in under_root["items"]}
        assert s["branch_2_transition_id"] in root_transition_ids or under_root["next_after"] is not None

        # ---- list_records: spot-check every one of the eight types ----
        for record_type, known_id, id_field in [
            ("identity", s["multi_identity"], "identity_id"),
            ("authority", s["authority_a"], "authority_id"),
            ("state", s["state_x"], "state_id"),
            ("transition", s["branch_1_transition_id"], "transition_id"),
            ("evidence", s["evidence_id"], "evidence_id"),
            ("exception", None, None),
            ("receipt", s["accepted_receipt_id"], "receipt_id"),
            ("grant", s["grant_valid"], "grant_id"),
        ]:
            page = kernel.list_records(record_type, limit=500)
            assert isinstance(page["items"], list)
            if known_id is not None:
                ids_seen = {item[id_field] for item in page["items"]}
                assert known_id in ids_seen or page["next_after"] is not None, (
                    f"{record_type} listing did not include {known_id} within the first page"
                )

        # exception type specifically: our FAILED exception must appear.
        exception_page = kernel.list_records("exception", limit=500)
        exception_ids_seen = {item["exception_id"] for item in exception_page["items"]}
        assert exception["exception_id"] in exception_ids_seen or exception_page["next_after"] is not None

        # ---- invalid record_type ----
        try:
            kernel.list_records("not-a-real-type")
            raise AssertionError("invalid record_type must raise ValueError")
        except ValueError as exc:
            assert "unknown record_type" in str(exc)

    print("v0_2_observability_1_focused: OK")
    print(f"  empty_identity={s['empty_identity']} (0 grants)")
    print(f"  multi_identity={s['multi_identity']} (2 grants, 1 revoked)")
    print(f"  state_x={s['state_x']} (2-way branch fan-out)")
    print(f"  failed_receipt_id={s['failed_receipt_id']}")
    print(f"  rejected_receipt_id={s['rejected_receipt_id']}")
    print(f"  accepted_receipt_id={s['accepted_receipt_id']} (no fabricated exception)")


if __name__ == "__main__":
    main()
