#!/usr/bin/env python3
"""Create a new EASTER database with a caller-selected Genesis identity."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).parent
SCHEMA_PATH = HERE / "schema.sql"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def initialize_database(
    db_path: str | Path,
    root_identity_id: str,
    *,
    root_identity_payload: dict[str, object] | None = None,
) -> Path:
    """Atomically create a fresh database without overwriting an existing path."""
    if not root_identity_id:
        raise ValueError("root_identity_id must not be empty")

    destination = Path(db_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"EASTER database already exists: {destination}")

    temporary = destination.with_name(
        f".{destination.name}.initialize-{secrets.token_hex(8)}.tmp"
    )
    created = False
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        created = True

        timestamp = _utc_now()
        identity_payload = (
            root_identity_payload
            if root_identity_payload is not None
            else {"role": "genesis_identity"}
        )
        with sqlite3.connect(temporary) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(SCHEMA_PATH.read_text())
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO identities (identity_id, created_at, payload) VALUES (?, ?, ?)",
                (
                    root_identity_id,
                    timestamp,
                    json.dumps(
                        identity_payload,
                        separators=(",", ":"),
                        sort_keys=True,
                        allow_nan=False,
                    ),
                ),
            )
            conn.execute(
                "INSERT INTO authorities (authority_id, created_at, is_root, payload) VALUES (?, ?, ?, ?)",
                (
                    "authority:root",
                    timestamp,
                    1,
                    json.dumps(
                        {"name": "root", "description": "Genesis root authority"},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO authority_grants
                    (grant_id, authority_seq, identity_id, authority_id,
                     granted_by_identity_id, created_at, valid_from, expires_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "grant:genesis-root", 1, root_identity_id, "authority:root", None,
                    timestamp, timestamp, None,
                    json.dumps(
                        {"genesis": 1, "reason": "Initial root authority bootstrap"},
                        separators=(",", ":"), sort_keys=True,
                    ),
                ),
            )
            conn.execute(
                "INSERT INTO states (state_id, created_at, payload) VALUES (?, ?, ?)",
                (
                    "state:genesis", timestamp,
                    json.dumps(
                        {"genesis": 1, "version": "0.1"},
                        separators=(",", ":"), sort_keys=True,
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO receipts
                    (receipt_id, operation_id, transition_id, outcome, created_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "receipt:genesis", "operation:genesis", None, "BOOTSTRAP", timestamp,
                    json.dumps(
                        {"genesis": 1, "description": "Intelligence Kernel v0.1 genesis bootstrap"},
                        separators=(",", ":"), sort_keys=True,
                    ),
                ),
            )
            conn.commit()

        with open(temporary, "rb") as database_file:
            os.fsync(database_file.fileno())

        # Atomic no-replace publish: link(2) fails if a concurrent initializer
        # won the destination race and cannot overwrite it.
        os.link(temporary, destination)
        os.unlink(temporary)
        created = False
        return destination
    finally:
        if created:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a fresh EASTER database with a chosen root identity."
    )
    parser.add_argument("db_path", type=Path, help="destination SQLite database path")
    parser.add_argument("root_identity_id", help="initial root identity id")
    args = parser.parse_args()
    initialize_database(args.db_path, args.root_identity_id)
    print(f"Initialized EASTER at {args.db_path} with root {args.root_identity_id}")


if __name__ == "__main__":
    main()
