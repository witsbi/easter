"""Issuance database and private-key storage for the EASTER Enterprise
token broker.

Owns ``issuance.db`` (broker-private, never read by the kernel) and
the Ed25519 issuance keypair. The private key value never appears in
a log line, an audit-log row, or any export this module produces --
every function that could plausibly be tempted to stringify a key
object instead stores/returns only a reference (an id, a fingerprint,
or a keychain lookup key), never the raw bytes, except at the single
point (``load_private_key``) where the caller explicitly asked to sign
something.

Key storage: OS keychain via the ``keyring`` package where a backend
is available (macOS Keychain, Windows Credential Locker, Linux Secret
Service / KWallet); a dedicated file with ``chmod 600`` otherwise.
``keys.privkey_ref`` records which one was used and how to find the
key again -- it is itself not a secret.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import keyring
import keyring.errors
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KEYRING_SERVICE = "easter-enterprise-broker"

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    id          TEXT PRIMARY KEY,
    alg         TEXT NOT NULL,
    pubkey      TEXT NOT NULL,
    privkey_ref TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('active', 'retired'))
);

CREATE TABLE IF NOT EXISTS tokens (
    jti         TEXT PRIMARY KEY,
    identity    TEXT NOT NULL,
    grants_json TEXT NOT NULL,
    key_id      TEXT NOT NULL REFERENCES keys(id),
    issued_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT,
    label       TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    action TEXT NOT NULL,
    actor  TEXT NOT NULL,
    jti    TEXT,
    detail TEXT NOT NULL DEFAULT '{}'
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_key_id() -> str:
    return f"key:{secrets.token_hex(16)}"


def new_jti() -> str:
    return f"jti:{secrets.token_hex(16)}"


class Issuance:
    """Owns ``issuance.db`` and the active issuance key's storage.

    Never reads the kernel database. Never imports ``kernel.py``.
    """

    def __init__(self, db_path: str | Path, key_dir: str | Path) -> None:
        self.db_path = Path(db_path)
        self.key_dir = Path(key_dir)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Private-key storage: keyring first, chmod-600 file fallback.
    # ------------------------------------------------------------------

    def _store_private_key(self, key_id: str, private_bytes: bytes) -> str:
        """Store raw Ed25519 private-key bytes. Returns an opaque ref,
        never the key material itself."""
        encoded = base64.b64encode(private_bytes).decode("ascii")
        try:
            keyring.set_password(KEYRING_SERVICE, key_id, encoded)
            # Confirm the backend actually persisted it rather than
            # silently no-op'ing (some backends do this when
            # unconfigured) -- read it back before trusting it.
            if keyring.get_password(KEYRING_SERVICE, key_id) != encoded:
                raise keyring.errors.KeyringError(
                    "keyring write did not round-trip"
                )
            return f"keyring:{KEYRING_SERVICE}:{key_id}"
        except (keyring.errors.KeyringError, RuntimeError):
            pass

        file_path = self.key_dir / f"{key_id}.key"
        file_path.write_bytes(private_bytes)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        return f"file:{file_path}"

    def _load_private_key(self, privkey_ref: str) -> Ed25519PrivateKey:
        kind, _, rest = privkey_ref.partition(":")
        if kind == "keyring":
            _, _, key_id = rest.partition(":")
            encoded = keyring.get_password(KEYRING_SERVICE, key_id)
            if encoded is None:
                raise RuntimeError(
                    f"issuance key missing from OS keychain: {key_id}"
                )
            raw = base64.b64decode(encoded)
        elif kind == "file":
            raw = Path(rest).read_bytes()
        else:
            raise ValueError(f"unrecognized privkey_ref kind: {privkey_ref!r}")
        return Ed25519PrivateKey.from_private_bytes(raw)

    # ------------------------------------------------------------------
    # Key lifecycle
    # ------------------------------------------------------------------

    def generate_key(self, *, actor: str) -> dict[str, Any]:
        """Generate a fresh Ed25519 issuance keypair, store the private
        half, and record the public half. Does not retire any existing
        key -- rotation with overlap is the caller's job (see
        ``rotate_key`` semantics in the token-broker spec section 8:
        the old public key stays registered until every token it
        signed has expired)."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = new_key_id()

        private_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        pubkey_b64 = base64.b64encode(
            public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")

        privkey_ref = self._store_private_key(key_id, private_bytes)
        created_at = utc_now()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO keys (id, alg, pubkey, privkey_ref, created_at, status)
                VALUES (?, 'ed25519', ?, ?, ?, 'active')
                """,
                (key_id, pubkey_b64, privkey_ref, created_at),
            )
        self._audit(actor=actor, action="KEY_GENERATE", jti=None, detail={"key_id": key_id})
        return {"key_id": key_id, "pubkey": pubkey_b64, "created_at": created_at}

    def retire_key(self, key_id: str, *, actor: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE keys SET status = 'retired' WHERE id = ?", (key_id,)
            )
        self._audit(actor=actor, action="KEY_RETIRE", jti=None, detail={"key_id": key_id})

    def active_key(self) -> dict[str, Any] | None:
        """The current signing key. Rotation may leave more than one
        'active' row only transiently; callers that mint should always
        use the most recently created active key."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, alg, pubkey, privkey_ref, created_at, status
                FROM keys WHERE status = 'active'
                ORDER BY created_at DESC LIMIT 1
                """
            ).fetchone()
        return dict(row) if row else None

    def get_private_key(self, key_id: str) -> Ed25519PrivateKey:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT privkey_ref FROM keys WHERE id = ?", (key_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"no such issuance key: {key_id}")
        return self._load_private_key(row["privkey_ref"])

    def get_public_key_b64(self, key_id: str) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT pubkey FROM keys WHERE id = ?", (key_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"no such issuance key: {key_id}")
        return row["pubkey"]

    def all_keys(self) -> list[dict[str, Any]]:
        """Metadata only -- never includes privkey_ref's referenced
        secret value, only the reference string itself (which is not
        a secret: it names a keychain entry or a file path, not key
        material)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, alg, pubkey, created_at, status FROM keys "
                "ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Token metadata (the signature itself is never stored -- it lives
    # only with the agent that holds the token)
    # ------------------------------------------------------------------

    def record_token(
        self,
        *,
        jti: str,
        identity: str,
        grants_json: str,
        key_id: str,
        issued_at: str,
        expires_at: str,
        label: str | None,
        actor: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tokens
                    (jti, identity, grants_json, key_id, issued_at, expires_at, label)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (jti, identity, grants_json, key_id, issued_at, expires_at, label),
            )
        self._audit(
            actor=actor,
            action="TOKEN_MINT",
            jti=jti,
            detail={"identity": identity, "grants": json.loads(grants_json)},
        )

    def revoke_token(self, jti: str, *, actor: str) -> bool:
        """Denylist a token by jti. Returns False if the jti is
        unknown (caller decides whether that's an error)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT revoked_at FROM tokens WHERE jti = ?", (jti,)
            ).fetchone()
            if row is None:
                return False
            if row["revoked_at"] is None:
                conn.execute(
                    "UPDATE tokens SET revoked_at = ? WHERE jti = ?",
                    (utc_now(), jti),
                )
        self._audit(actor=actor, action="TOKEN_REVOKE", jti=jti, detail={})
        return True

    def is_revoked(self, jti: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT revoked_at FROM tokens WHERE jti = ?", (jti,)
            ).fetchone()
        # An unknown jti is treated as revoked by the caller's policy
        # (gateway side), not here -- this method answers only "does
        # the issuance DB have a live record for this jti."
        return row is None or row["revoked_at"] is not None

    def list_tokens(self, *, identity: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if identity is not None:
                rows = conn.execute(
                    "SELECT * FROM tokens WHERE identity = ? ORDER BY issued_at DESC",
                    (identity,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tokens ORDER BY issued_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Audit log (the broker's own log -- the kernel's Evidence record,
    # written separately by the caller via kernel_client.py, is the
    # authoritative counterpart per the spec)
    # ------------------------------------------------------------------

    def _audit(
        self, *, actor: str, action: str, jti: str | None, detail: dict[str, Any]
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, action, actor, jti, detail) "
                "VALUES (?, ?, ?, ?, ?)",
                (utc_now(), action, actor, jti, json.dumps(detail)),
            )

    def audit_log(self, *, limit: int = 500) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, ts, action, actor, jti, detail FROM audit_log "
                "ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
