"""Read-only view of the token broker's issuance database.

The gateway needs two pieces of broker state while authenticating a signed
token: the public key named by ``kid`` and whether the token's ``jti`` is
denylisted. Keeping that access in this module preserves the gateway's
existing no-direct-SQLite boundary and, more importantly, opens the database
with SQLite's ``mode=ro`` flag so authentication code cannot mutate broker
state accidentally.
"""

from __future__ import annotations

import base64
import binascii
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class IssuanceReadError(Exception):
    """The issuance database could not be read safely."""


class IssuanceReader:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path).resolve()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # mode=ro is an enforced SQLite boundary: a missing path fails rather
        # than creating a new database, and this connection cannot write.
        uri = f"file:{quote(str(self._db_path))}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True)
        except sqlite3.Error as exc:
            raise IssuanceReadError("issuance database unavailable") from exc
        try:
            yield conn
        finally:
            conn.close()

    def resolve_public_key(self, key_id: str) -> Ed25519PublicKey | None:
        """None for an unknown key id *or* a revoked one -- the caller
        (``tokens.verify``) cannot tell the two apart, by design: a
        revoked key must fail exactly like an unregistered one, not
        surface a distinguishable error an attacker could use to probe
        key status. A retired key still resolves (rotation overlap is
        intentional); only 'revoked' is excluded."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT pubkey FROM keys WHERE id = ? AND status != 'revoked'",
                    (key_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise IssuanceReadError("issuance key lookup failed") from exc
        if row is None:
            return None
        try:
            raw = base64.b64decode(row[0], validate=True)
            return Ed25519PublicKey.from_public_bytes(raw)
        except (binascii.Error, TypeError, ValueError) as exc:
            raise IssuanceReadError("issuance public key is invalid") from exc

    def is_denylisted(self, jti: str) -> bool:
        """Return true for unknown or explicitly revoked token identifiers."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT revoked_at FROM tokens WHERE jti = ?", (jti,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise IssuanceReadError("issuance token lookup failed") from exc
        return row is None or row[0] is not None
