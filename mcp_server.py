#!/usr/bin/env python3
"""
EASTER-MCP-0 -- Thin Boundary

The first MCP boundary over Intelligence Kernel v0.1.

This is an adapter, not a new semantic layer. Every tool below is a
thin pass-through to an existing, already-supported Kernel v0.1
Python method -- same name, same arguments, same return shape. No
tool here invents application semantics, selects a preferred branch,
evaluates Evidence, or determines a canonical State.

Kernel v0.1 (kernel.py / schema.sql) is not modified to build this
adapter. Where the existing Kernel API has no supported method for
something MCP-0 was asked to expose (Exception retrieval, lineage/
history inspection), that operation is simply not implemented here --
see MCP_0_RECEIPT.md for the recorded friction.

This module deliberately never imports sqlite3 and never opens
data/kernel.db (or any other .db file) itself. All kernel interaction
goes through a single `Kernel` instance and its public methods. See
mcp_0_3_no_direct_sqlite.py, which asserts this structurally by
reading this file's own source.

Authority note: reaching a tool over MCP transport is not the same as
holding valid Kernel Authority. A tool call always transports; the
Kernel decides, independently, whether the presented
authority_grant_id is still valid. See mcp_0_2_authority_boundary.py.
"""

from __future__ import annotations

import functools
import os
from typing import Any, Callable, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from kernel import Kernel, KernelError

KERNEL_DB_PATH = os.environ.get("KERNEL_DB_PATH")

kernel = Kernel(KERNEL_DB_PATH) if KERNEL_DB_PATH else Kernel()

F = TypeVar("F", bound=Callable[..., Any])


def surface_kernel_rejections(fn: F) -> F:
    """Let a deliberate rejection reach the MCP caller instead of being masked.

    The MCP SDK deliberately hides an arbitrary exception's text from
    the client (it treats an unannotated exception as a server-side
    crash, not a deliberate outcome). A KernelError is not a crash:
    - A KernelError is the Kernel deliberately and correctly
      rejecting an operation under its own existing Authority/State
      semantics (e.g. "authority grant has been revoked: ..."),
      already carrying a receipt id for that rejection.
    Re-raising it as ToolError is the one thing this adapter must do
    for a caller to see *why* a call was rejected rather than just
    that something failed -- it changes no Kernel behavior, only how
    this boundary reports an outcome the Kernel already produced.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except KernelError as exc:
            raise ToolError(str(exc)) from exc

    return wrapper  # type: ignore[return-value]

server = MCPServer(
    "intelligence-kernel-mcp-0",
    instructions=(
        "Thin MCP boundary over Intelligence Kernel v0.1. Tools map "
        "1:1 onto the existing supported Kernel Python API. MCP "
        "transport access does not imply Kernel Authority -- calls "
        "made with an invalid or revoked authority_grant_id will "
        "transport successfully and come back as a tool error."
    ),
)


# ------------------------------------------------------------------
# State retrieval
# ------------------------------------------------------------------


@server.tool()
def get_state(state_id: str) -> dict[str, Any] | None:
    """Retrieve a committed State by state_id, or null if it does not exist."""
    return kernel.get_state(state_id)


@server.tool()
def get_genesis_state() -> dict[str, Any] | None:
    """Retrieve the genesis State (state:genesis)."""
    return kernel.get_genesis_state()


# ------------------------------------------------------------------
# Evidence recording
# ------------------------------------------------------------------


@server.tool()
@surface_kernel_rejections
def record_evidence(
    requester_identity_id: str,
    authority_grant_id: str,
    payload: dict[str, Any],
) -> dict[str, str]:
    """Admit a new immutable Evidence object under a currently valid grant."""
    return kernel.record_evidence(
        requester_identity_id=requester_identity_id,
        authority_grant_id=authority_grant_id,
        payload=payload,
    )


# ------------------------------------------------------------------
# Transition submission
# ------------------------------------------------------------------


@server.tool()
@surface_kernel_rejections
def transition(
    requester_identity_id: str,
    from_state_id: str,
    authority_grant_id: str,
    new_state_payload: dict[str, Any],
    transition_payload: dict[str, Any] | None = None,
    evidence_ids: list[str] | None = None,
    new_identities: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Commit an authoritative State transition under a currently valid grant."""
    return kernel.transition(
        requester_identity_id=requester_identity_id,
        from_state_id=from_state_id,
        authority_grant_id=authority_grant_id,
        new_state_payload=new_state_payload,
        transition_payload=transition_payload,
        evidence_ids=evidence_ids,
        new_identities=new_identities,
    )


# ------------------------------------------------------------------
# Receipt retrieval
# ------------------------------------------------------------------


@server.tool()
def get_receipt(receipt_id: str) -> dict[str, Any] | None:
    """Retrieve a Receipt by receipt_id, or null if it does not exist."""
    return kernel.get_receipt(receipt_id)


# ------------------------------------------------------------------
# Authority: grant retrieval, definition, grant, revoke, revoke_all
# ------------------------------------------------------------------


@server.tool()
def get_grant(grant_id: str) -> dict[str, Any] | None:
    """Retrieve an authority grant by grant_id, or null if it does not exist."""
    return kernel.get_grant(grant_id)


@server.tool()
@surface_kernel_rejections
def define_authority(
    requester_identity_id: str,
    authority_grant_id: str,
    authority_id: str,
    is_root: bool = False,
    payload: dict[str, Any] | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, str]:
    """Define a new Authority. Requires a currently valid root grant."""
    return kernel.define_authority(
        requester_identity_id=requester_identity_id,
        authority_grant_id=authority_grant_id,
        authority_id=authority_id,
        is_root=is_root,
        payload=payload,
        evidence_ids=evidence_ids,
    )


@server.tool()
@surface_kernel_rejections
def grant(
    requester_identity_id: str,
    authority_grant_id: str,
    identity_id: str,
    authority_id: str,
    valid_from: str | None = None,
    expires_at: str | None = None,
    payload: dict[str, Any] | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, str]:
    """Grant an existing Authority to an existing identity. Requires a currently valid root grant."""
    return kernel.grant(
        requester_identity_id=requester_identity_id,
        authority_grant_id=authority_grant_id,
        identity_id=identity_id,
        authority_id=authority_id,
        valid_from=valid_from,
        expires_at=expires_at,
        payload=payload,
        evidence_ids=evidence_ids,
    )


@server.tool()
@surface_kernel_rejections
def revoke(
    requester_identity_id: str,
    authority_grant_id: str,
    grant_id: str,
    reason: str | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, str]:
    """Revoke a specific authority grant. Requires a currently valid root grant."""
    return kernel.revoke(
        requester_identity_id=requester_identity_id,
        authority_grant_id=authority_grant_id,
        grant_id=grant_id,
        reason=reason,
        evidence_ids=evidence_ids,
    )


@server.tool()
@surface_kernel_rejections
def revoke_all(
    requester_identity_id: str,
    authority_grant_id: str,
    identity_id: str,
    reason: str | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, str]:
    """Revoke every grant an identity currently holds. Requires a currently valid root grant."""
    return kernel.revoke_all(
        requester_identity_id=requester_identity_id,
        authority_grant_id=authority_grant_id,
        identity_id=identity_id,
        reason=reason,
        evidence_ids=evidence_ids,
    )


# ------------------------------------------------------------------
# Observability (v0.2) -- read-only, accepted subset only. See
# V0_2_OBSERVABILITY_DESIGN.md section 0 for what was accepted vs.
# deferred, and V0_2_OBSERVABILITY_RECEIPT.md for implementation
# evidence. Same rule as every tool above: thin pass-through, same
# name/arguments/return shape as the Kernel method, zero new MCP-side
# semantics. Pagination cursors (`after`) pass through as opaque
# strings -- this adapter never constructs, parses, or interprets one.
# ------------------------------------------------------------------


@server.tool()
def get_identity(identity_id: str) -> dict[str, Any] | None:
    """Retrieve an Identity by identity_id, or null if it does not exist."""
    return kernel.get_identity(identity_id)


@server.tool()
def get_authority(authority_id: str) -> dict[str, Any] | None:
    """Retrieve an Authority by authority_id, or null if it does not exist."""
    return kernel.get_authority(authority_id)


@server.tool()
def get_evidence(evidence_id: str) -> dict[str, Any] | None:
    """Retrieve an Evidence record by evidence_id, or null if it does not exist."""
    return kernel.get_evidence(evidence_id)


@server.tool()
def get_transition(transition_id: str) -> dict[str, Any] | None:
    """Retrieve a Transition by transition_id, or null if it does not exist."""
    return kernel.get_transition(transition_id)


@server.tool()
def get_exception_by_receipt(receipt_id: str) -> dict[str, Any] | None:
    """Retrieve the Exception associated with a Receipt, or null if none exists.

    Only REJECTED/FAILED receipts ever have one; an ACCEPTED or
    BOOTSTRAP receipt_id returns null -- this never fabricates a
    placeholder Exception for a receipt that never had one.
    """
    return kernel.get_exception_by_receipt(receipt_id)


@server.tool()
@surface_kernel_rejections
def list_grants_for_identity(
    identity_id: str,
    after: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Every Grant ever issued to this identity, oldest first, paginated.

    Includes revoked and expired grants -- existence in this list is
    not validity. Call is_grant_revoked/validate_grant separately for
    current-validity questions. Ordering uses the kernel-enforced
    authority sequence and is authoritative append order.
    """
    return kernel.list_grants_for_identity(identity_id, after=after, limit=limit)


@server.tool()
@surface_kernel_rejections
def list_transitions_from_state(
    state_id: str,
    after: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Every Transition with from_state_id = state_id, oldest first, paginated.

    Multiple results mean multiple branches from this State -- all
    are returned with no ordering that implies which is preferred.
    For this record type, oldest-first ordering is a stable
    created_at/transition_id walk, not authoritative commit order,
    causality, or branch precedence.
    """
    return kernel.list_transitions_from_state(state_id, after=after, limit=limit)


@server.tool()
@surface_kernel_rejections
def list_transitions_by_grant(
    authority_grant_id: str,
    after: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Every Transition authorized by this grant, oldest first, paginated.

    Ordering is a stable created_at/transition_id walk, not
    authoritative commit order or causality.
    """
    return kernel.list_transitions_by_grant(authority_grant_id, after=after, limit=limit)


@server.tool()
@surface_kernel_rejections
def list_records(
    record_type: str,
    after: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Every record of record_type, oldest/earliest-appended first, paginated.

    record_type must be one of: identity, authority, state, transition,
    receipt, evidence, exception, grant. Each item has exactly the
    shape the corresponding get_<type> tool would return for that id.
    For identity, authority, state, transition, evidence, and
    exception, oldest-first ordering is a stable created_at/primary-key
    walk, not authoritative commit order, causality, or precedence.
    Receipt and grant ordering uses their kernel-enforced append
    sequences.
    An unrecognized record_type is rejected as a tool error naming the
    valid set, not silently accepted or crashed on.
    """
    try:
        return kernel.list_records(record_type, after=after, limit=limit)
    except ValueError as exc:
        # This is the intentional v0.2 input-validation boundary. Keep
        # it local so the frozen v0.1 write-tool decorator above remains
        # KernelError-only.
        raise ToolError(str(exc)) from exc


if __name__ == "__main__":
    server.run(transport="stdio")
