# EASTER-MCP-0 Receipt — Thin Boundary

**Status: implemented, tested, stopped at scope per brief.**

## What was implemented

`mcp_server.py` — a single-file MCP server (official `mcp` Python SDK,
v2.2.0, stdio transport) exposing the existing, already-supported
Kernel v0.1 Python API 1:1 as MCP tools. Every tool is a thin
pass-through: same name, same keyword arguments, same return shape as
the corresponding `Kernel` method. No tool interprets State payloads,
selects a preferred branch, evaluates Evidence, or invents application
concepts.

Tools exposed (all of the operations the brief asked for that the
existing Kernel API actually supports):

| Tool | Kernel method |
|---|---|
| `get_state` | `Kernel.get_state` |
| `get_genesis_state` | `Kernel.get_genesis_state` |
| `record_evidence` | `Kernel.record_evidence` |
| `transition` | `Kernel.transition` |
| `get_receipt` | `Kernel.get_receipt` |
| `get_grant` | `Kernel.get_grant` |
| `define_authority` | `Kernel.define_authority` |
| `grant` | `Kernel.grant` |
| `revoke` | `Kernel.revoke` |
| `revoke_all` | `Kernel.revoke_all` |

One adapter-level decision beyond pure pass-through: a `KernelError`
(and its `AuthorityError`/`StateError` subclasses) raised by a write
operation is re-raised as the MCP SDK's own `ToolError` inside
`surface_kernel_rejections` (`mcp_server.py`). Without this, the SDK's
default crash-masking hides *why* an operation was rejected from the
caller — a Kernel rejection is a deliberate, correct outcome (already
carrying a receipt id), not a server crash. This changes no Kernel
behavior; it only changes which of the SDK's two built-in error
categories the adapter classifies an already-existing Kernel exception
into.

Dependencies: `requirements-mcp.txt` (`mcp==2.2.0`), installed into a
local `.venv/` (gitignored). No other repo files were changed.

**`kernel.py` and `schema.sql` were not modified.**

## Runtime evidence

Three executable scripts, no pytest, matching this repo's existing
`authority_N_*.py` / `state_N_*.py` / `evidence_N_*.py` / `receipt_N_*.py`
regression-script convention. All three run against a throwaway
`shutil.copy2` of `data/kernel.db` in `/tmp` (same convention as
`receipt_2_minimality.py`); none touch the tracked dev database.

### `mcp_0_1_vertical_slice.py` — `get_state → record_evidence → transition → get_receipt`

Launches `mcp_server.py` as a **real subprocess** speaking MCP over
stdio (actual JSON-RPC messages across a pipe, not an in-process
function call), drives it with a real `mcp.ClientSession`, then opens
a **second, independent** `Kernel` instance directly against the same
on-disk db file (never through MCP) to confirm the records the MCP
tool calls claim to have produced are genuinely committed — including
querying `receipt_evidence` directly to confirm the Evidence citation
landed. Example passing run:

```
mcp_0_1_vertical_slice: OK
  state_id=state:435c0b33-6ef7-4b71-9bfa-418d8708b989
  transition_id=transition:3c5a7a3f-b182-450b-9816-b06f4bcdbdd5
  evidence_id=evidence:266ffbae-33fa-4326-bf16-f60e7171e804
  receipt_id=receipt:420ae85f-5b61-4edf-9a8a-590bd80c1a8b
```

### `mcp_0_2_authority_boundary.py` — MCP access ≠ Kernel Authority

Runs the full 7-step sequence from the brief over real MCP stdio
transport: root grants → agent transitions (succeeds) → root revokes →
agent retains MCP transport access and attempts another transition (the
call transports normally and returns a `CallToolResult`, it is not
dropped or refused at the transport layer) → **Kernel rejects it**
under its own existing Authority semantics → root grants again → agent
transitions again (succeeds). Example passing run:

```
Tool 'transition' failed: 'Error executing tool transition: authority grant has been revoked: grant:e7c85592-a789-4a7e-952a-35835a0bc597 [receipt=receipt:95b86298-1c85-4ec4-915e-7183746b0922]'
mcp_0_2_authority_boundary: OK
  agent_identity_id=identity:mcp-0-test-agent-65b629f6
  authority_id=authority:mcp-0-test-op-65b629f6
  first_grant_id=grant:e7c85592-a789-4a7e-952a-35835a0bc597 (authorized, then revoked, then rejected)
  second_grant_id=grant:730bb63f-cfb6-4504-a341-c08b2eb34c2c (authorized again after re-grant)
```

The logged line is the Kernel's own `AuthorityError` message
(`authority grant has been revoked: ...`), reaching the MCP caller
via `surface_kernel_rejections` — the test asserts on that exact text
and on `is_error=True`, not merely "something failed."

### `mcp_0_3_no_direct_sqlite.py` — structural boundary check

A runtime probe can only show what one test run happened to do, so
this is a static, AST-level check of `mcp_server.py`'s own source:
asserts no `sqlite3` import, no `.execute(`/`.cursor(`/`.connect(`
calls, no string literal naming a `.db` file, only
`Kernel`/`KernelError`/`AuthorityError`/`StateError` imported from
`kernel.py`, and exactly one shared module-level `Kernel(...)`
instance (never constructed fresh inside a tool function). Passes.

All three scripts were run consecutively immediately before writing
this receipt; results above are from that run.

## Whether Kernel v0.1 required modification

**No.** `kernel.py` and `schema.sql` are unchanged from `main` at the
whole-kernel-composition-review state (PR #11, merge commit
`8981b6e7feee86ad3e8cecda590413abbcf49ed2`).

## Boundary friction discovered

Two operations the brief asked MCP-0 to expose have **no supported
Kernel API today**. Per the brief's own instruction ("record friction
rather than changing kernel semantics"), Nathan explicitly chose
Option B: neither is implemented in MCP-0.

1. **Exception retrieval.** `exceptions` is an authoritative,
   append-only table (`exception_id`, `receipt_id`, `created_at`,
   `payload`) but `kernel.py` has no `get_exception(exception_id)` —
   only `get_receipt(receipt_id)` exists, with no equivalent for the
   diagnostic detail an Exception carries.
2. **Lineage/history inspection.** `transitions.from_state_id` /
   `to_state_id` is the sole authoritative source of State lineage
   (`states.parent_state_id` was deliberately removed per
   `schema.sql`'s own comments), and `idx_transitions_from_state`
   exists in the schema anticipating this query — but no `kernel.py`
   method walks it. There is no supported way to ask "what transitions
   led from this state" or "what is this state's ancestry" without
   reaching around the Kernel.

A third, smaller friction point surfaced while building the adapter
itself (not something the brief asked to expose, but relevant to any
future MCP-facing Kernel work): the `mcp` Python SDK's default
behavior masks an arbitrary raised exception's message from the MCP
caller, treating it as an unannotated server crash. A Kernel
`KernelError` is a deliberate, correct rejection (it already carries
its own receipt id), not a crash — MCP-0 handles this by re-raising it
as the SDK's `ToolError` (see `surface_kernel_rejections`), which is
adapter-side classification, not a Kernel change, but it's worth
naming as boundary friction: any other MCP adapter built against this
Kernel will hit the same masking unless it does the same translation.

## Candidate v0.2 issues (recorded, not implemented)

- Add a Kernel-supported read path for Exception retrieval
  (`get_exception(exception_id)` or equivalent), symmetric with the
  existing `get_receipt`/`get_grant`/`get_state` getters.
- Add a Kernel-supported read path for lineage/history inspection
  (e.g. "transitions from a given state_id", "ancestry of a given
  state_id"), using the existing `transitions.from_state_id` /
  `to_state_id` columns and `idx_transitions_from_state` index — no
  new schema needed, only a new Kernel method.

Neither issue was implemented here — MCP-0 stops at what Kernel v0.1
actually supports today, per the brief.

## Stop condition

MCP-0 satisfies its stated criteria: the four-tool vertical slice runs
end-to-end against a real subprocess over real MCP transport with
independently-verified kernel-side evidence; all remaining supported
operations are exposed; the Authority test demonstrates MCP access ≠
Kernel Authority; the adapter is structurally verified to never touch
SQLite directly; Kernel v0.1 was not modified; friction and candidate
v0.2 issues are recorded above. Stopping here — no agent orchestration,
memory, branch-selection policy, or permissions UI was added.
