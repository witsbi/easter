"""Receipt operation-id cardinality and migration regression checks."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from initialize import initialize_database
from kernel import Kernel, KernelError


REPO = Path(__file__).resolve().parent.parent
MIGRATION = REPO / "migrations" / "migrate_receipts_unique_operation_id.sql"


def receipt_count(kernel: Kernel, operation_id: str) -> int:
    with kernel.connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM receipts WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()[0]


def assert_duplicate_rejected(
    kernel: Kernel,
    operation_id: str,
    outcome: str,
) -> None:
    before = receipt_count(kernel, operation_id)
    try:
        kernel.record_failure(
            operation_id=operation_id,
            outcome=outcome,
            reason="duplicate terminal outcome probe",
        )
    except KernelError as exc:
        assert str(exc) == (
            f"operation already has a terminal Receipt: {operation_id}"
        )
        assert "UNIQUE constraint failed" not in str(exc)
    else:
        raise AssertionError("duplicate operation_id must be rejected")
    assert receipt_count(kernel, operation_id) == before == 1


def exercise_kernel_cardinality(db_path: Path) -> None:
    initialize_database(db_path, "identity:nathan")
    kernel = Kernel(db_path)

    failed_operation = "operation:receipt-3-failed"
    failed_receipt = kernel.record_failure(
        operation_id=failed_operation,
        outcome="FAILED",
        reason="legitimate first-use caller-supplied operation id",
    )
    assert kernel.get_receipt(failed_receipt)["outcome"] == "FAILED"
    assert_duplicate_rejected(kernel, failed_operation, "FAILED")
    assert_duplicate_rejected(kernel, failed_operation, "REJECTED")

    rejected_operation = "operation:receipt-3-rejected"
    rejected_receipt = kernel.record_failure(
        operation_id=rejected_operation,
        outcome="REJECTED",
        reason="legitimate first-use rejected operation",
    )
    assert kernel.get_receipt(rejected_receipt)["outcome"] == "REJECTED"
    assert_duplicate_rejected(kernel, rejected_operation, "REJECTED")
    assert_duplicate_rejected(kernel, rejected_operation, "FAILED")

    accepted = kernel.transition(
        requester_identity_id="identity:nathan",
        from_state_id="state:genesis",
        authority_grant_id="grant:genesis-root",
        new_state_payload={"probe": "receipt-3-accepted"},
    )
    assert kernel.get_receipt(accepted["receipt_id"])["outcome"] == "ACCEPTED"
    assert_duplicate_rejected(kernel, accepted["operation_id"], "FAILED")
    assert_duplicate_rejected(kernel, accepted["operation_id"], "REJECTED")

    assert kernel.get_receipt("receipt:genesis")["outcome"] == "BOOTSTRAP"
    assert_duplicate_rejected(kernel, "operation:genesis", "FAILED")
    assert_duplicate_rejected(kernel, "operation:genesis", "REJECTED")

    # The database constraint, not an application pre-check, is authoritative.
    with kernel.connect() as conn:
        try:
            conn.execute(
                """
                INSERT INTO receipts (
                    receipt_id, operation_id, transition_id,
                    outcome, created_at, payload
                ) VALUES (?, ?, NULL, 'ACCEPTED', ?, '{}')
                """,
                (
                    "receipt:receipt-3-direct-duplicate",
                    accepted["operation_id"],
                    "2026-10-01T00:00:00Z",
                ),
            )
        except sqlite3.IntegrityError as exc:
            assert "receipts.operation_id" in str(exc)
        else:
            raise AssertionError("schema must reject duplicate operation_id")

    with kernel.connect() as conn:
        outcomes = {
            row[0]
            for row in conn.execute("SELECT outcome FROM receipts").fetchall()
        }
    assert outcomes == {"BOOTSTRAP", "ACCEPTED", "REJECTED", "FAILED"}


def create_legacy_receipts_db(path: Path, *, duplicate: bool) -> list[tuple]:
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE receipts (
                receipt_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                operation_id TEXT NOT NULL,
                transition_id TEXT,
                outcome TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload))
            );
            CREATE INDEX idx_receipts_operation ON receipts(operation_id);
            """
        )
        rows = [
            (1, "receipt:legacy-1", "operation:legacy-1", None, "BOOTSTRAP", "2026-01-01T00:00:00Z", "{}"),
            (2, "receipt:legacy-2", "operation:legacy-2", None, "FAILED", "2026-01-01T00:00:01Z", "{}"),
        ]
        if duplicate:
            rows.append(
                (3, "receipt:legacy-3", "operation:legacy-2", None, "REJECTED", "2026-01-01T00:00:02Z", "{}")
            )
        conn.executemany(
            "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return rows


def exercise_migration(directory: Path) -> None:
    migration_sql = MIGRATION.read_text()

    compatible = directory / "compatible.db"
    original_rows = create_legacy_receipts_db(compatible, duplicate=False)
    with sqlite3.connect(compatible) as conn:
        conn.executescript(migration_sql)
        migrated_rows = conn.execute(
            "SELECT * FROM receipts ORDER BY receipt_seq"
        ).fetchall()
        index_is_unique = conn.execute(
            "SELECT [unique] FROM pragma_index_list('receipts') "
            "WHERE name = 'idx_receipts_operation_unique'"
        ).fetchone()[0]
    assert migrated_rows == original_rows
    assert index_is_unique == 1

    incompatible = directory / "incompatible.db"
    duplicate_rows = create_legacy_receipts_db(incompatible, duplicate=True)
    with sqlite3.connect(incompatible) as conn:
        try:
            conn.executescript(migration_sql)
        except sqlite3.IntegrityError as exc:
            assert "receipts.operation_id" in str(exc)
            conn.rollback()
        else:
            raise AssertionError("migration must fail closed on historical duplicates")
        preserved_rows = conn.execute(
            "SELECT * FROM receipts ORDER BY receipt_seq"
        ).fetchall()
        index_is_unique = conn.execute(
            "SELECT [unique] FROM pragma_index_list('receipts') "
            "WHERE name = 'idx_receipts_operation_unique'"
        ).fetchone()
    assert preserved_rows == duplicate_rows
    assert index_is_unique is None


with tempfile.TemporaryDirectory(prefix="receipt-3-") as directory_name:
    directory = Path(directory_name)
    exercise_kernel_cardinality(directory / "kernel.db")
    exercise_migration(directory)

print("receipt_3_operation_id_uniqueness: OK")