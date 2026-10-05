"""EASTER Enterprise token broker -- admin-channel-only HTTP API.

Routes: POST /mint, POST /revoke-token, GET /list, POST /rotate-key,
GET /health. Per the approved gateway-auth design, there is no
human-auth code path anywhere in this module: using the admin channel
(loopback, or a unix socket in a later hardening pass) IS the
step-up. This app binds loopback only, the same posture ``gateway.py``
and ``console.py`` already take, and is never meant to be reachable
from the agent-facing network path at all.

The broker never reads the kernel (hard boundary from the spec). It
mints and tracks tokens in its own ``issuance.db``. It still *writes*
to the kernel for exactly one reason: every mint/revoke/rotation must
be recorded as EASTER Evidence citing the grant IDs involved (spec
section 9). Like ``console.py``, this module never assumes which
identity/grant that write happens under -- the caller (the wizard/
admin backend, acting for a human operator) supplies
``requester_identity_id``/``authority_grant_id`` explicitly on every
call that touches the kernel.
"""

from __future__ import annotations

import contextlib
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from broker import tokens
from broker.issuance import Issuance, new_jti
from broker.kernel_client import KernelMCPClient

# v1 pins the token role to "agent" -- the token-broker spec names
# "agent" as the only v1 role ("roles beyond agent are later work").
# A caller supplying anything else is a caller bug, not a request to
# silently honor or silently ignore.
V1_ROLE = "agent"

HERE = Path(__file__).resolve().parent
DEFAULT_ISSUANCE_DB = HERE.parent / "data" / "issuance.db"
DEFAULT_KEY_DIR = HERE.parent / "data" / "broker-keys"


class BrokerError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def _require(body: dict[str, Any], *fields: str) -> None:
    missing = [f for f in fields if f not in body or body[f] in (None, "")]
    if missing:
        raise BrokerError(f"missing required field(s): {', '.join(missing)}")


def _parse_ttl(ttl_seconds: Any) -> timedelta:
    """Validate a caller-supplied ttl_seconds into a timedelta, or
    raise BrokerError (400) -- never a bare ValueError/TypeError
    escaping the route handler as an unhandled 500. The upper bound
    (24h) is also enforced inside tokens.mint() itself; checking it
    here too means a bad request fails with a clean 400 instead of
    tripping that function's internal ValueError."""
    if ttl_seconds is None:
        return tokens.DEFAULT_TTL
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise BrokerError("ttl_seconds must be an integer number of seconds")
    if ttl_seconds <= 0:
        raise BrokerError("ttl_seconds must be positive")
    ttl = timedelta(seconds=ttl_seconds)
    if ttl > tokens.DEFAULT_TTL:
        raise BrokerError(
            f"ttl_seconds exceeds the {int(tokens.DEFAULT_TTL.total_seconds())}s policy cap"
        )
    return ttl


def _parse_role(body: dict[str, Any]) -> str:
    """v1 accepts an explicit role only if it is exactly V1_ROLE; an
    absent role defaults to it. Any other value is rejected rather
    than silently coerced or silently ignored."""
    role = body.get("role", V1_ROLE)
    if role != V1_ROLE:
        raise BrokerError(f"role must be '{V1_ROLE}' in v1; got {role!r}")
    return role


async def _record_evidence(
    kernel: KernelMCPClient,
    *,
    requester_identity_id: str,
    authority_grant_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    is_error, result = await kernel.call(
        "record_evidence",
        {
            "requester_identity_id": requester_identity_id,
            "authority_grant_id": authority_grant_id,
            "payload": payload,
        },
    )
    if is_error:
        raise BrokerError(f"kernel rejected evidence recording: {result}", status=502)
    return result


def make_app(issuance: Issuance, kernel: KernelMCPClient) -> Starlette:
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "easter-enterprise-broker-0"})

    async def mint(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

        try:
            _require(
                body,
                "requester_identity_id",
                "authority_grant_id",
                "identity",
                "grants",
            )
            role = _parse_role(body)
            ttl = _parse_ttl(body.get("ttl_seconds"))

            key_row = issuance.active_key()
            if key_row is None:
                raise BrokerError(
                    "no active issuance key -- run key generation first", status=503
                )

            # Everything above and through tokens.mint() is pure
            # computation -- no durable write anywhere yet. If the
            # Evidence write below fails, nothing has to be rolled
            # back, because nothing has been committed: the signed
            # token bytes exist only in this function's local
            # variables and are never returned to the caller unless
            # the kernel has already accepted the accountability
            # record for them.
            private_key = issuance.get_private_key(key_row["id"])
            jti = new_jti()
            token_str, claims = tokens.mint(
                private_key=private_key,
                key_id=key_row["id"],
                identity=body["identity"],
                grants=list(body["grants"]),
                jti=jti,
                role=role,
                label=body.get("label"),
                ttl=ttl,
            )

            evidence = await _record_evidence(
                kernel,
                requester_identity_id=body["requester_identity_id"],
                authority_grant_id=body["authority_grant_id"],
                payload={
                    "kind": "broker_token_mint",
                    "jti": jti,
                    "identity": claims.sub,
                    "grants": claims.grants,
                    "key_id": key_row["id"],
                    "issued_at": claims.iat,
                    "expires_at": claims.exp,
                    "label": claims.lbl,
                },
            )

            # Only now, with the kernel's accountability record already
            # confirmed, does the mint become durable on the broker's
            # own side.
            issuance.record_token(
                jti=jti,
                identity=claims.sub,
                grants_json=json.dumps(claims.grants),
                key_id=key_row["id"],
                issued_at=claims.iat,
                expires_at=claims.exp,
                label=claims.lbl,
                actor=body["requester_identity_id"],
            )

            return JSONResponse(
                {
                    "ok": True,
                    "token": token_str,
                    "jti": jti,
                    "expires_at": claims.exp,
                    "evidence_id": evidence.get("evidence_id"),
                    "receipt_id": evidence.get("receipt_id"),
                }
            )
        except BrokerError as exc:
            return JSONResponse({"error": exc.message}, status_code=exc.status)

    async def revoke_token(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

        try:
            _require(body, "jti", "requester_identity_id", "authority_grant_id")
            jti = body["jti"]

            # Pure read first: decide whether this call changes
            # anything before writing any accountability record for a
            # change that may not happen.
            row = issuance.get_token(jti)
            if row is None:
                raise BrokerError(f"unknown jti: {jti}", status=404)

            if row["revoked_at"] is not None:
                # Already revoked (e.g. a retried request, or a race
                # with a concurrent revoke of the same jti). No new
                # state change occurs, so no new Evidence is written
                # either -- this also avoids receipt-spam for repeated
                # revoke calls on the same token.
                return JSONResponse(
                    {"ok": True, "revoked": True, "already_revoked": True}
                )

            evidence = await _record_evidence(
                kernel,
                requester_identity_id=body["requester_identity_id"],
                authority_grant_id=body["authority_grant_id"],
                payload={
                    "kind": "broker_token_revoke",
                    "jti": jti,
                    "reason": body.get("reason", ""),
                },
            )

            # Only now, with the kernel's accountability record already
            # confirmed, does the revocation become durable. mark_revoked
            # re-checks revoked_at IS NULL itself, so a concurrent revoke
            # that won the race between our read above and this write is
            # at most a harmless redundant no-op here, never a double
            # effect.
            issuance.mark_revoked(jti, actor=body["requester_identity_id"])

            return JSONResponse(
                {
                    "ok": True,
                    "revoked": True,
                    "evidence_id": evidence.get("evidence_id"),
                    "receipt_id": evidence.get("receipt_id"),
                }
            )
        except BrokerError as exc:
            return JSONResponse({"error": exc.message}, status_code=exc.status)

    async def list_tokens(request: Request) -> JSONResponse:
        identity = request.query_params.get("identity")
        rows = issuance.list_tokens(identity=identity)
        return JSONResponse({"ok": True, "tokens": rows})

    async def rotate_key(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

        try:
            _require(body, "requester_identity_id", "authority_grant_id")
            old_key = issuance.active_key()

            # Pure in-memory generation -- no keychain write, no row,
            # no audit entry yet. Discarding this on an error path
            # below has nothing to clean up.
            private_key, new_key_id, new_pubkey_b64 = issuance.prepare_new_key()

            evidence = await _record_evidence(
                kernel,
                requester_identity_id=body["requester_identity_id"],
                authority_grant_id=body["authority_grant_id"],
                payload={
                    "kind": "broker_key_rotation",
                    "new_key_id": new_key_id,
                    "new_pubkey": new_pubkey_b64,
                    "retired_key_id": old_key["id"] if old_key else None,
                },
            )

            # Only now, with the kernel's accountability record already
            # confirmed, does the new key become durable and the old
            # one retired.
            new_key = issuance.commit_new_key(
                private_key,
                new_key_id,
                new_pubkey_b64,
                actor=body["requester_identity_id"],
            )
            if old_key is not None:
                # Deliberately NOT revoking old tokens: rotation with
                # overlap means the old key stays valid for
                # verification (it is not deleted, only no longer
                # used for new mints) until every token it signed has
                # expired naturally, per spec section 8.
                issuance.retire_key(
                    old_key["id"], actor=body["requester_identity_id"]
                )

            return JSONResponse(
                {
                    "ok": True,
                    "new_key_id": new_key["key_id"],
                    "new_pubkey": new_key["pubkey"],
                    "retired_key_id": old_key["id"] if old_key else None,
                    "evidence_id": evidence.get("evidence_id"),
                    "receipt_id": evidence.get("receipt_id"),
                }
            )
        except BrokerError as exc:
            return JSONResponse({"error": exc.message}, status_code=exc.status)

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        await kernel.start()
        try:
            yield
        finally:
            await kernel.stop()

    return Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/mint", mint, methods=["POST"]),
            Route("/revoke-token", revoke_token, methods=["POST"]),
            Route("/list", list_tokens, methods=["GET"]),
            Route("/rotate-key", rotate_key, methods=["POST"]),
        ],
        lifespan=lifespan,
    )


def _build_parser():
    import argparse

    parser = argparse.ArgumentParser(description="EASTER Enterprise token broker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--issuance-db", default=str(DEFAULT_ISSUANCE_DB))
    parser.add_argument("--key-dir", default=str(DEFAULT_KEY_DIR))
    parser.add_argument("--kernel-db", default=os.environ.get("KERNEL_DB_PATH"))
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(
            "refusing to bind outside loopback -- the broker's admin API "
            "has no authentication of its own; loopback is the trust boundary"
        )
    issuance = Issuance(args.issuance_db, args.key_dir)
    kernel = KernelMCPClient(args.kernel_db)
    app = make_app(issuance, kernel)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
