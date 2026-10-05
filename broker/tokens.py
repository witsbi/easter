"""Ed25519-signed compact agent tokens.

Format: ``base64url(header) . base64url(payload) . base64url(signature)``,
per the token-broker spec section 4. The kernel/gateway verify these
with only the issuance public key -- no database lookup, no new
kernel state, no network call back to the broker except the
denylist/jti check the gateway already needs to do.

Header carries ``kid`` (the issuance key id) in addition to ``alg``/
``typ``. The spec's own payload-claims list does not enumerate header
fields, but a ``kid`` is necessary, not decorative: key rotation with
overlap (spec section 8) means two keys -- the retiring one and the
new one -- can both have live, unexpired tokens in flight at once, so
a verifier needs to know which registered public key a given token
claims to be signed by before it can check the signature at all. This
mirrors ordinary JWT practice and does not change the claims payload
shape the spec decided.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TOKEN_TYP = "easter-agent-token"
TOKEN_VERSION = "v1"
DEFAULT_TTL = timedelta(hours=24)


class TokenError(Exception):
    """A token failed to verify. The message is safe to return to a
    caller -- it never includes key material or the raw token."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@dataclass(frozen=True)
class Claims:
    typ: str
    sub: str
    grants: list[str]
    role: str
    iat: str
    exp: str
    jti: str
    lbl: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "typ": self.typ,
            "sub": self.sub,
            "grants": self.grants,
            "role": self.role,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
            "lbl": self.lbl,
        }

    def is_expired(self, *, at: datetime | None = None) -> bool:
        return (at or _utc_now()) >= _parse_iso(self.exp)


def mint(
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    identity: str,
    grants: list[str],
    jti: str,
    role: str = "agent",
    label: str | None = None,
    ttl: timedelta = DEFAULT_TTL,
) -> tuple[str, Claims]:
    """Sign a fresh compact token. Returns (token_string, claims) --
    the caller is responsible for persisting the claims metadata
    (``issuance.record_token``) and recording EASTER Evidence; this
    function only produces bytes, it never touches a database."""
    if ttl > timedelta(hours=24):
        raise ValueError("token TTL may not exceed the 24h policy cap")

    now = _utc_now()
    claims = Claims(
        typ=TOKEN_TYP,
        sub=identity,
        grants=list(grants),
        role=role,
        iat=_iso(now),
        exp=_iso(now + ttl),
        jti=jti,
        lbl=label,
    )

    header = {"alg": "EdDSA", "typ": TOKEN_VERSION, "kid": key_id}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(
        json.dumps(claims.as_dict(), separators=(",", ":")).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}", claims


def verify(
    token: str,
    *,
    resolve_public_key: Callable[[str], Ed25519PublicKey | None],
    at: datetime | None = None,
) -> Claims:
    """Verify signature, structure, and expiry. Does NOT check the
    denylist -- that is a stateful broker/gateway concern, deliberately
    kept separate from the stateless cryptographic check here.

    ``resolve_public_key`` maps a header ``kid`` to the registered
    Ed25519 public key for that key id, or None if unknown/retired
    past its grace window. Kept as an injected callable so this module
    never has to know about the issuance database directly -- tokens.py
    is pure crypto plus claims shape, nothing else.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed token: expected 3 dot-separated parts")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except (binascii.Error, TypeError, UnicodeError, ValueError) as exc:
        raise TokenError("malformed token: undecodable segment") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("malformed token: header and payload must be objects")

    if header.get("alg") != "EdDSA" or header.get("typ") != TOKEN_VERSION:
        raise TokenError("unsupported token header")

    kid = header.get("kid")
    if not isinstance(kid, str):
        raise TokenError("token header missing kid")

    public_key = resolve_public_key(kid)
    if public_key is None:
        raise TokenError(f"unknown or unregistered issuance key: {kid}")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise TokenError("signature verification failed") from exc

    try:
        claims = Claims(
            typ=payload["typ"],
            sub=payload["sub"],
            grants=list(payload["grants"]),
            role=payload["role"],
            iat=payload["iat"],
            exp=payload["exp"],
            jti=payload["jti"],
            lbl=payload.get("lbl"),
        )
    except (KeyError, TypeError) as exc:
        raise TokenError("token payload missing required claim") from exc

    if (
        not isinstance(claims.typ, str)
        or not isinstance(claims.sub, str)
        or not claims.sub
        or not isinstance(payload.get("grants"), list)
        or not all(isinstance(grant, str) and grant for grant in claims.grants)
        or not isinstance(claims.role, str)
        or not claims.role
        or not isinstance(claims.iat, str)
        or not isinstance(claims.exp, str)
        or not isinstance(claims.jti, str)
        or not claims.jti
        or (claims.lbl is not None and not isinstance(claims.lbl, str))
    ):
        raise TokenError("token payload contains invalid claim types")

    if claims.typ != TOKEN_TYP:
        raise TokenError(f"unexpected token typ: {claims.typ!r}")

    try:
        if claims.is_expired(at=at):
            raise TokenError("token expired")
        _parse_iso(claims.iat)
    except (TypeError, ValueError) as exc:
        raise TokenError("token payload contains invalid timestamp") from exc

    return claims
