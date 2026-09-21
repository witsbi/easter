"""EASTER Kernel v0.2 observability: adversarial/composition tests.

Attacks the nine accepted methods (V0_2_OBSERVABILITY_DESIGN.md
section 0) for exactly the accidental semantics the design's own
adversarial section (9) and the implementation brief both name:

    latest == current
    first == preferred
    grant exists == grant valid
    receipt accepted == state correct
    evidence exists == evidence true
    payload field == kernel relationship

No assertion in this file requires any of those interpretations to
hold -- several assertions actively require them NOT to hold.

Runs against a throwaway /tmp copy of data/kernel.db.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

from kernel import Kernel

HERE = Path(__file__).parent
ROOT = "grant:genesis-root"
NATHAN = "identity:nathan"
GENESIS = "state:genesis"


def build_scenario(kernel: Kernel) -> dict:
    empty_identity = "identity:v0-2-adv-empty"
    multi_identity = "identity:v0-2-adv-multi"
    authority_id = "authority:v0-2-adv-authority"

    setup = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=GENESIS,
        authority_grant_id=ROOT,
        new_state_payload={"probe": "v0-2-adversarial-setup"},
        new_identities=[
            {"identity_id": empty_identity, "payload": {}},
            {"identity_id": multi_identity, "payload": {}},
        ],
    )
    state_x = setup["state_id"]

    kernel.define_authority(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        authority_id=authority_id,
        is_root=False,
    )

    grant_a = kernel.grant(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        identity_id=multi_identity,
        authority_id=authority_id,
    )["grant_id"]

    # Double-revoke: revoke() has no guard against revoking an
    # already-revoked grant a second time (V0_2_OBSERVABILITY_DESIGN.md
    # section 2.3). This is a genuine, reproducible v0.1 behavior --
    # not a v0.2 bug -- and this test exists specifically to prove
    # v0.2's new read methods do not paper over it.
    kernel.revoke(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        grant_id=grant_a,
        reason="v0-2-adversarial: first revoke",
    )
    kernel.revoke(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        grant_id=grant_a,
        reason="v0-2-adversarial: second, redundant revoke",
    )

    grant_b = kernel.grant(
        requester_identity_id=NATHAN,
        authority_grant_id=ROOT,
        identity_id=multi_identity,
        authority_id=authority_id,
    )["grant_id"]

    # Three-way branch fan-out from one state, under two different grants.
    t1 = kernel.transition(
        requester_identity_id=multi_identity,
        from_state_id=state_x,
        authority_grant_id=grant_b,
        new_state_payload={"probe": "v0-2-adversarial-branch-1"},
    )
    t2 = kernel.transition(
        requester_identity_id=NATHAN,
        from_state_id=state_x,
        authority_grant_id=ROOT,
        new_state_payload={"probe": "v0-2-adversarial-branch-2"},
    )
    t3 = kernel.transition(
        requester_identity_id=multi_identity,
        from_state_id=state_x,
        authority_grant_id=grant_b,
        new_state_payload={"probe": "v0-2-adversarial-branch-3"},
    )

    return {
        "empty_identity": empty_identity,
        "multi_identity": multi_identity,
        "authority_id": authority_id,
        "state_x": state_x,
        "grant_a_double_revoked": grant_a,
        "grant_b_valid": grant_b,
        "branch_transition_ids": {t1["transition_id"], t2["transition_id"], t3["transition_id"]},
        "grant_b_transition_ids": {t1["transition_id"], t3["transition_id"]},
    }


def full_table_count(db_path: Path, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def walk_all(kernel: Kernel, record_type: str, page_size: int) -> list[dict]:
    """Page through list_records with a small page size, asserting no
    duplicates and a stable, terminating walk -- the "stable
    continuation with after" and "pagination boundaries" checks."""
    seen_ids = []
    after = None
    id_field = {
        "identity": "identity_id",
        "authority": "authority_id",
        "state": "state_id",
        "transition": "transition_id",
        "receipt": "receipt_id",
        "evidence": "evidence_id",
        "exception": "exception_id",
        "grant": "grant_id",
    }[record_type]

    pages = 0
    while True:
        page = kernel.list_records(record_type, after=after, limit=page_size)
        assert len(page["items"]) <= page_size
        for item in page["items"]:
            seen_ids.append(item[id_field])
        pages += 1
        if page["next_after"] is None:
            break
        after = page["next_after"]
        assert pages < 10_000, "pagination did not terminate -- possible infinite loop"

    assert len(seen_ids) == len(set(seen_ids)), f"{record_type}: pagination produced duplicates"
    return seen_ids


def main() -> None:
    source = HERE / "data" / "kernel.db"
    with tempfile.NamedTemporaryFile(prefix="v0-2-adversarial-", suffix=".db") as f:
        f.close()
        db_path = Path(f.name)
        shutil.copy2(source, db_path)
        kernel = Kernel(db_path)

        s = build_scenario(kernel)

        # ============================================================
        # Unknown IDs / empty result sets
        # ============================================================
        assert kernel.get_identity("identity:nope") is None
        assert kernel.get_authority("authority:nope") is None
        assert kernel.get_evidence("evidence:nope") is None
        assert kernel.get_transition("transition:nope") is None
        assert kernel.get_exception_by_receipt("receipt:nope") is None
        assert kernel.list_grants_for_identity("identity:nope") == {"items": [], "next_after": None}
        assert kernel.list_transitions_from_state("state:nope") == {"items": [], "next_after": None}
        assert kernel.list_transitions_by_grant("grant:nope") == {"items": [], "next_after": None}

        # Identity with zero grants -> genuinely empty, not an error.
        assert kernel.list_grants_for_identity(s["empty_identity"]) == {"items": [], "next_after": None}

        # ============================================================
        # Invalid record_type / invalid limits
        # ============================================================
        for bad_type in ["", "identities", "Identity", "revocation", None]:
            try:
                kernel.list_records(bad_type)  # type: ignore[arg-type]
                raise AssertionError(f"record_type {bad_type!r} should have raised ValueError")
            except ValueError:
                pass
            except TypeError:
                pass  # None fails the `in frozenset` check's hashing path fine, but guard just in case

        # limit <= 0 clamps to the minimum (1), never zero, never an error.
        clamped_low = kernel.list_records("identity", limit=0)
        assert len(clamped_low["items"]) == 1
        clamped_negative = kernel.list_records("identity", limit=-5)
        assert len(clamped_negative["items"]) == 1

        # limit far above the max clamps to _LIST_MAX_LIMIT, never unbounded.
        clamped_high = kernel.list_records("receipt", limit=10_000_000)
        assert len(clamped_high["items"]) <= Kernel._LIST_MAX_LIMIT
        assert len(clamped_high["items"]) == Kernel._LIST_MAX_LIMIT, (
            "receipts table must have more rows than the max limit for this "
            "assertion to be meaningful -- confirmed true for this dev db copy"
        )

        # ============================================================
        # Pagination boundaries + stable continuation with `after`,
        # for both cursor kinds (authoritative int, and compound
        # wall-clock+pk) -- and enumeration never silently drops or
        # duplicates a record ("enumeration never selecting a
        # preferred record").
        # ============================================================
        for record_type, table in [
            ("identity", "identities"),
            ("authority", "authorities"),
            ("state", "states"),
            ("transition", "transitions"),
            ("evidence", "evidence"),
            ("exception", "exceptions"),
            ("receipt", "receipts"),
            ("grant", "authority_grants"),
        ]:
            walked_ids = walk_all(kernel, record_type, page_size=7)
            real_count = full_table_count(db_path, table)
            assert len(walked_ids) == real_count, (
                f"{record_type}: paginated walk saw {len(walked_ids)} records, "
                f"table has {real_count} -- enumeration must return every record, "
                f"not a filtered/preferred subset"
            )

        # ============================================================
        # Branch fan-out from one State: all three returned, no
        # ordering that implies a "main" branch.
        # ============================================================
        branches = kernel.list_transitions_from_state(s["state_x"])
        assert len(branches["items"]) == 3
        assert {i["transition_id"] for i in branches["items"]} == s["branch_transition_ids"]

        # ============================================================
        # Multiple transitions under one Grant.
        # ============================================================
        under_grant_b = kernel.list_transitions_by_grant(s["grant_b_valid"])
        assert {i["transition_id"] for i in under_grant_b["items"]} == s["grant_b_transition_ids"]
        assert len(under_grant_b["items"]) == 2

        # ============================================================
        # Identities with zero vs. multiple Grants.
        # ============================================================
        assert kernel.list_grants_for_identity(s["empty_identity"])["items"] == []
        multi_grants = kernel.list_grants_for_identity(s["multi_identity"])["items"]
        assert {g["grant_id"] for g in multi_grants} == {s["grant_a_double_revoked"], s["grant_b_valid"]}

        # ============================================================
        # grant exists == grant valid: must NOT hold. The double-
        # revoked grant is still returned by list_grants_for_identity
        # -- existence, not current validity.
        # ============================================================
        assert s["grant_a_double_revoked"] in {g["grant_id"] for g in multi_grants}
        assert kernel.is_grant_revoked(s["grant_a_double_revoked"]) is True, (
            "the pre-existing is_grant_revoked() must independently confirm this "
            "grant is actually revoked -- listing it and it being invalid are two "
            "separate facts, both true here, neither implying the other"
        )

        # ============================================================
        # Multiple revocation history remaining representable: no
        # accepted v0.2 method lists revocations directly this round
        # (list_revocations_affecting_grant is deferred), but this
        # implementation must not have silently collapsed the two
        # REVOKE rows the double-revoke above produced, and
        # list_grants_for_identity must not be corrupted by them
        # (e.g. via an accidental join that duplicates the grant row).
        # ============================================================
        conn = sqlite3.connect(db_path)
        try:
            revoke_rows = conn.execute(
                "SELECT revocation_id FROM authority_grant_revocations WHERE grant_id = ?",
                (s["grant_a_double_revoked"],),
            ).fetchall()
        finally:
            conn.close()
        assert len(revoke_rows) == 2, (
            "expected both REVOKE rows from the double-revoke to still exist, "
            f"found {len(revoke_rows)}"
        )
        grant_a_appearances = [g for g in multi_grants if g["grant_id"] == s["grant_a_double_revoked"]]
        assert len(grant_a_appearances) == 1, (
            "the double-revoked grant must appear exactly once in "
            "list_grants_for_identity, not once per revocation row"
        )

        # ============================================================
        # receipt accepted == state correct: must NOT hold. outcome is
        # returned verbatim; nothing about "correctness" is asserted
        # or computed anywhere in these methods.
        # ============================================================
        # Simplest direct check: outcome field is exactly what was stored, no
        # derived "correctness" field exists anywhere in the returned shape.
        any_receipt = kernel.list_records("receipt", limit=1)["items"][0]
        assert set(any_receipt.keys()) == {
            "receipt_id", "operation_id", "transition_id", "outcome", "created_at", "payload"
        }, "no additional 'correctness'/'valid'/'trusted' field may be synthesized onto a receipt"

        # ============================================================
        # evidence exists == evidence true: must NOT hold. No proposed
        # method asserts, verifies, or scores evidence truth -- payload
        # is returned as opaque content only. (Covered more directly in
        # v0_2_observability_1_focused.py's misleading-evidence-payload
        # test; here we just confirm the shape carries no truth/score field.)
        # ============================================================
        any_evidence = kernel.list_records("evidence", limit=1)["items"][0]
        assert set(any_evidence.keys()) == {"evidence_id", "created_at", "payload"}

        # ============================================================
        # payload field == kernel relationship: must NOT hold. Put an
        # evidence payload that looks exactly like grant/transition
        # provenance and confirm it is never picked up by any
        # relationship query.
        # ============================================================
        decoy_evidence_id = kernel.record_evidence(
            requester_identity_id=NATHAN,
            authority_grant_id=ROOT,
            payload={
                "identity_id": s["multi_identity"],
                "authority_grant_id": s["grant_b_valid"],
                "grant_id": "grant:totally-fabricated-by-payload",
                "from_state_id": s["state_x"],
            },
        )["evidence_id"]

        grants_after_decoy = kernel.list_grants_for_identity(s["multi_identity"])["items"]
        assert "grant:totally-fabricated-by-payload" not in {g["grant_id"] for g in grants_after_decoy}
        assert len(grants_after_decoy) == 2, "the decoy evidence payload must not manufacture a new grant"

        transitions_after_decoy = kernel.list_transitions_by_grant(s["grant_b_valid"])["items"]
        assert transitions_after_decoy == under_grant_b["items"], (
            "the decoy evidence payload must not manufacture a new transition "
            "under grant_b_valid"
        )
        assert kernel.get_evidence(decoy_evidence_id)["payload"]["grant_id"] == (
            "grant:totally-fabricated-by-payload"
        ), "the decoy payload itself is still returned verbatim as opaque evidence content"

    print("v0_2_observability_2_adversarial: OK")
    print(f"  paginated full-count walk verified for all 8 record_type values")
    print(f"  double-revoked grant={s['grant_a_double_revoked']} -- both REVOKE rows preserved")
    print(f"  branch fan-out from state_x: {len(s['branch_transition_ids'])} transitions, none preferred")
    print(f"  decoy evidence payload confirmed inert for grant/transition relationship queries")


if __name__ == "__main__":
    main()
