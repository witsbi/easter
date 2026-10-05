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
            key_row = issuance.active_key()
            if key_row is None:
                raise BrokerError(
                    "no active issuance key -- run key generation first", status=503
                )

            private_key = issuance.get_private_key(key_row["id"])
            jti = new_jti()
            ttl_seconds = body.get("ttl_seconds")
            ttl = (
                tokens.DEFAULT_TTL
                if ttl_seconds is None
                else timedelta(seconds=int(ttl_seconds))
            )

            token_str, claims = tokens.mint(
                private_key=private_key,
                key_id=key_row["id"],
                identity=body["identity"],
                grants=list(body["grants"]),
                jti=jti,
                role=body.get("role", "agent"),
                label=body.get("label"),
                ttl=ttl,
            )

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
            found = issuance.revoke_token(
                body["jti"], actor=body["requester_identity_id"]
            )
            if not found:
                raise BrokerError(f"unknown jti: {body['jti']}", status=404)

            evidence = await _record_evidence(
                kernel,
                requester_identity_id=body["requester_identity_id"],
                authority_grant_id=body["authority_grant_id"],
                payload={
                    "kind": "broker_token_revoke",
                    "jti": body["jti"],
                    "reason": body.get("reason", ""),
                },
            )
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

            new_key = issuance.generate_key(actor=body["requester_identity_id"])
            if old_key is not None:
                # Deliberately NOT revoking old tokens: rotation with
                # overlap means the old key stays valid for
                # verification (it is not deleted, only no longer
                # used for new mints) until every token it signed has
                # expired naturally, per spec section 8.
                issuance.retire_key(
                    old_key["id"], actor=body["requester_identity_id"]
                )

            evidence = await _record_evidence(
                kernel,
                requester_identity_id=body["requester_identity_id"],
                authority_grant_id=body["authority_grant_id"],
                payload={
                    "kind": "broker_key_rotation",
                    "new_key_id": new_key["key_id"],
                    "new_pubkey": new_key["pubkey"],
                    "retired_key_id": old_key["id"] if old_key else None,
                },
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
