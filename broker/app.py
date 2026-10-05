"""EASTER Enterprise token broker -- admin-channel-only HTTP API.

Routes: POST /mint, POST /revoke-token, POST /revoke-key, GET /list,
POST /rotate-key, POST /reconcile, GET /health. Per the approved
gateway-auth design, there is no human-auth code path anywhere in this
module: using the admin channel (loopback, or a unix socket in a later
hardening pass) IS the step-up. This app binds loopback only, the same
posture ``gateway.py`` and ``console.py`` already take, and is never
meant to be reachable from the agent-facing network path at all.

The broker never reads the kernel (hard boundary from the spec). It
mints and tracks tokens in its own ``issuance.db``. It still *writes*
to the kernel for exactly one reason: every mint/revoke/rotation must
be recorded as EASTER Evidence citing the grant IDs involved (spec
section 9). Like ``console.py``, this module never assumes which
identity/grant that write happens under -- the caller (the wizard/
admin backend, acting for a human operator) supplies
``requester_identity_id``/``authority_grant_id`` explicitly on every
call that touches the kernel.

Every consequential handler (mint/revoke-token/revoke-key/rotate-key)
follows the same three-step shape, per the Setup Wizard's Decision 5
invariant ("a consequential operation reaches terminal completion only
when its durable effect and canonical accountability record agree"):

1. Claim this operation's natural key (``issuance.claim_operation``).
   This is the concurrency-control point -- two concurrent requests
   for the same logical effect (e.g. two revokes of the same jti, or
   two rotations from the same active key) can never both hold a
   claim, so only one of them ever reaches the kernel.
2. Record kernel Evidence. On failure, release the claim -- nothing
   durable happened, so there is nothing to roll back (Fix 1, PR #35
   round 1).
3. Only now, with the claim marked evidence-confirmed, perform the
   broker-local durable write and delete the claim. If the process
   dies between steps 2 and 3, the claim row survives with
   evidence_id/receipt_id attached, naming exactly what the kernel
   already confirmed -- ``/reconcile`` finishes step 3 later using
   that same recorded identity, never inventing a new one.

Known gap: a crash between steps 1 and 2 (claim made, kernel not yet
called) leaves a 'claimed' row that /reconcile deliberately does not
touch -- it cannot distinguish "crashed" from "still in flight," and
guessing wrong risks letting a live request's protection be stolen out
from under it. Such rows are visible via ``issuance.list_stale_claims``
for an operator to judge by age, but clearing them is not automated.
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

            # jti is 128-bit random, so claiming its op_key only ever
            # blocks a genuine replay of this exact attempt (e.g.
            # /reconcile), never two distinct mint requests -- there is
            # no shared resource for two different mints to race on.
            op_key = f"mint:{jti}"
            record_token_args = dict(
                jti=jti,
                identity=claims.sub,
                grants_json=json.dumps(claims.grants),
                key_id=key_row["id"],
                issued_at=claims.iat,
                expires_at=claims.exp,
                label=claims.lbl,
                actor=body["requester_identity_id"],
            )
            if not issuance.claim_operation(op_key, "mint", record_token_args):
                raise BrokerError("mint already in progress for this jti", status=409)

            try:
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
            except BrokerError:
                issuance.release_claim(op_key)
                raise

            # The kernel's accountability record is now confirmed. If
            # the process dies before record_token below runs, this
            # fact survives in the operations row for /reconcile to
            # finish -- it is never silently lost (Finding 2).
            issuance.mark_evidence_confirmed(
                op_key,
                evidence_id=evidence.get("evidence_id"),
                receipt_id=evidence.get("receipt_id"),
            )
            issuance.record_token(**record_token_args)
            issuance.complete_operation(op_key)

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
                # Already revoked (e.g. a retried request, or a
                # concurrent revoke that already completed). No new
                # state change occurs, so no new Evidence is written
                # either -- this also avoids receipt-spam for repeated
                # revoke calls on the same token.
                return JSONResponse(
                    {"ok": True, "revoked": True, "already_revoked": True}
                )

            # Claim this jti's revoke before calling the kernel. If a
            # second request for the same jti reaches here while this
            # one is still in flight (both can observe revoked_at IS
            # NULL above before either finishes), only one of them wins
            # this claim -- the other gets 409 and writes no Evidence
            # at all, rather than both independently recording an
            # accountability record for one logical state change
            # (Finding 3: the race is real precisely because the read
            # above and the write below are not one atomic step; this
            # claim is what makes the pair atomic in effect).
            op_key = f"revoke:{jti}"
            if not issuance.claim_operation(
                op_key, "revoke", {"jti": jti, "actor": body["requester_identity_id"]}
            ):
                raise BrokerError("revoke already in progress for this jti", status=409)

            try:
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
            except BrokerError:
                issuance.release_claim(op_key)
                raise

            # Only now, with the kernel's accountability record already
            # confirmed, does the revocation become durable.
            issuance.mark_evidence_confirmed(
                op_key,
                evidence_id=evidence.get("evidence_id"),
                receipt_id=evidence.get("receipt_id"),
            )
            issuance.mark_revoked(jti, actor=body["requester_identity_id"])
            issuance.complete_operation(op_key)

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

    async def revoke_key(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

        try:
            _require(body, "key_id", "requester_identity_id", "authority_grant_id")
            key_id = body["key_id"]

            key_row = issuance.get_key(key_id)
            if key_row is None:
                raise BrokerError(f"unknown key_id: {key_id}", status=404)

            if key_row["status"] == "revoked":
                return JSONResponse(
                    {"ok": True, "revoked": True, "already_revoked": True}
                )

            # Same claim-before-kernel-call shape as revoke_token, for
            # the same reason: two concurrent revoke-key calls for the
            # same key_id must not both record kernel Evidence for one
            # logical key-level revocation.
            op_key = f"revoke_key:{key_id}"
            if not issuance.claim_operation(
                op_key,
                "revoke_key",
                {"key_id": key_id, "actor": body["requester_identity_id"]},
            ):
                raise BrokerError(
                    "key revocation already in progress for this key_id", status=409
                )

            try:
                evidence = await _record_evidence(
                    kernel,
                    requester_identity_id=body["requester_identity_id"],
                    authority_grant_id=body["authority_grant_id"],
                    payload={
                        "kind": "broker_key_revoke",
                        "key_id": key_id,
                        "reason": body.get("reason", ""),
                    },
                )
            except BrokerError:
                issuance.release_claim(op_key)
                raise

            # Only now does the key become durably REVOKED: every token
            # it signed fails verification immediately afterward
            # (reader.IssuanceReader.resolve_public_key refuses to
            # resolve a revoked key at all), including ones this
            # issuance.db cannot individually enumerate by jti --
            # unlike retire_key (rotation overlap), this is one-way.
            issuance.mark_evidence_confirmed(
                op_key,
                evidence_id=evidence.get("evidence_id"),
                receipt_id=evidence.get("receipt_id"),
            )
            issuance.revoke_key(key_id, actor=body["requester_identity_id"])
            issuance.complete_operation(op_key)

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
            old_key_id = old_key["id"] if old_key else None

            # Pure in-memory generation -- no keychain write, no row,
            # no audit entry yet. Discarding this on an error path
            # below has nothing to clean up.
            private_key, new_key_id, new_pubkey_b64 = issuance.prepare_new_key()

            # Claimed against the *old* key's id, not the new one: two
            # concurrent rotations both reading the same active key as
            # "old" are racing to retire the same key and must not both
            # succeed independently (Finding 4's "concurrent rotations
            # may create a related state" -- two simultaneously-minted
            # replacement keys would both end up 'active' with neither
            # rotation aware of the other). new_key_id is always fresh
            # random and so cannot itself be the serialization point.
            op_key = f"rotate_from:{old_key_id or 'none'}"
            if not issuance.claim_operation(
                op_key,
                "rotate",
                {
                    "new_key_id": new_key_id,
                    "old_key_id": old_key_id,
                    "actor": body["requester_identity_id"],
                },
            ):
                raise BrokerError(
                    "a rotation from this key is already in progress", status=409
                )

            try:
                evidence = await _record_evidence(
                    kernel,
                    requester_identity_id=body["requester_identity_id"],
                    authority_grant_id=body["authority_grant_id"],
                    payload={
                        "kind": "broker_key_rotation",
                        "new_key_id": new_key_id,
                        "new_pubkey": new_pubkey_b64,
                        "retired_key_id": old_key_id,
                    },
                )
            except BrokerError:
                issuance.release_claim(op_key)
                raise

            issuance.mark_evidence_confirmed(
                op_key,
                evidence_id=evidence.get("evidence_id"),
                receipt_id=evidence.get("receipt_id"),
            )

            # Only now, with the kernel's accountability record already
            # confirmed, does the new key become durable. If this
            # itself fails, the private key material generated above
            # exists only in this request's memory and is now gone --
            # minting a replacement here would describe a key the
            # Evidence just recorded never named, which is exactly the
            # fabricated-history outcome Decision 5 forbids. Flag it
            # for manual reconciliation instead of guessing (Finding 2).
            try:
                new_key = issuance.commit_new_key(
                    private_key,
                    new_key_id,
                    new_pubkey_b64,
                    actor=body["requester_identity_id"],
                )
            except Exception:
                issuance.mark_needs_manual_reconciliation(op_key)
                raise BrokerError(
                    "kernel accountability for this rotation was recorded, but "
                    "the new key could not be persisted and its key material "
                    "is lost; this requires manual reconciliation",
                    status=500,
                )

            # The new key is durably active; only retiring the old one
            # remains, and that step needs no secret material -- a
            # crash here is always auto-reconcilable (see /reconcile).
            issuance.mark_key_committed(op_key)
            if old_key_id is not None:
                # Deliberately retiring, not revoking: rotation with
                # overlap means the old key stays valid for
                # verification (it is not deleted, only no longer
                # used for new mints) until every token it signed has
                # expired naturally, per spec section 8.
                issuance.retire_key(old_key_id, actor=body["requester_identity_id"])
            issuance.complete_operation(op_key)

            return JSONResponse(
                {
                    "ok": True,
                    "new_key_id": new_key["key_id"],
                    "new_pubkey": new_key["pubkey"],
                    "retired_key_id": old_key_id,
                    "evidence_id": evidence.get("evidence_id"),
                    "receipt_id": evidence.get("receipt_id"),
                }
            )
        except BrokerError as exc:
            return JSONResponse({"error": exc.message}, status_code=exc.status)

    async def reconcile(request: Request) -> JSONResponse:
        """Resolve disagreement between confirmed kernel Evidence and
        a broker-local durable effect that did not land -- never calls
        the kernel again for an operation it already confirmed; only
        finishes (or, for the one case it cannot safely finish,
        explicitly flags) the local write, preserving the original
        operation's evidence_id/receipt_id throughout. See the module
        docstring for the 'claimed'-row gap this intentionally does not
        touch."""
        reconciled: list[str] = []
        still_needs_attention: list[dict[str, Any]] = []
        for op in issuance.list_unresolved_operations():
            op_key = op["op_key"]
            kind = op["kind"]
            status = op["status"]
            detail = json.loads(op["detail"])
            try:
                if kind == "mint" and status == "evidence_confirmed":
                    issuance.record_token(**detail)
                    issuance.complete_operation(op_key)
                    reconciled.append(op_key)
                elif kind == "revoke" and status == "evidence_confirmed":
                    issuance.mark_revoked(detail["jti"], actor=detail["actor"])
                    issuance.complete_operation(op_key)
                    reconciled.append(op_key)
                elif kind == "revoke_key" and status == "evidence_confirmed":
                    issuance.revoke_key(detail["key_id"], actor=detail["actor"])
                    issuance.complete_operation(op_key)
                    reconciled.append(op_key)
                elif kind == "rotate" and status == "key_committed":
                    old_key_id = detail.get("old_key_id")
                    if old_key_id is not None:
                        issuance.retire_key(old_key_id, actor=detail["actor"])
                    issuance.complete_operation(op_key)
                    reconciled.append(op_key)
                elif kind == "rotate" and status == "evidence_confirmed":
                    # commit_new_key itself never landed -- see the
                    # rotate_key handler's comment: the key material is
                    # gone, and this cannot be auto-healed without
                    # fabricating a key the cited Evidence never named.
                    issuance.mark_needs_manual_reconciliation(op_key)
                    still_needs_attention.append(op)
                else:
                    still_needs_attention.append(op)
            except Exception as exc:
                still_needs_attention.append({**op, "last_error": str(exc)})
        return JSONResponse(
            {
                "ok": True,
                "reconciled": reconciled,
                "needs_attention": still_needs_attention,
            }
        )

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
            Route("/revoke-key", revoke_key, methods=["POST"]),
            Route("/list", list_tokens, methods=["GET"]),
            Route("/rotate-key", rotate_key, methods=["POST"]),
            Route("/reconcile", reconcile, methods=["POST"]),
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
