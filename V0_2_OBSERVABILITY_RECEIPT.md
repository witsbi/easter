# EASTER v0.2 Observability Receipt

**Status: READY_FOR_REVIEW**

**Date:** 2026-09-21

## 1. Scope and surviving API

The implemented v0.2 observability surface is exactly the nine methods
accepted in section 0 of `V0_2_OBSERVABILITY_DESIGN.md`:

### Kernel methods

- `get_identity(identity_id)`
- `get_authority(authority_id)`
- `get_evidence(evidence_id)`
- `get_transition(transition_id)`
- `get_exception_by_receipt(receipt_id)`
- `list_grants_for_identity(identity_id, after=None, limit=50)`
- `list_transitions_from_state(state_id, after=None, limit=50)`
- `list_transitions_by_grant(authority_grant_id, after=None, limit=50)`
- `list_records(record_type, after=None, limit=50)`

### MCP tools

The same nine names and argument/return shapes are exposed 1:1 through
`mcp_server.py`. The adapter does not interpret cursors or add semantics.

Unknown single-record lookups remain Kernel `None`. The MCP SDK represents a
successful `None` result as `CallToolResult(content=[])`; the v0.2 boundary
test now decodes that established transport representation as `None`. The
adapter was not changed to invent a not-found object or error. This matches
the existing Console-0 MCP client convention.

## 2. Explicitly deferred

These five analyzed candidates remain absent from both Kernel and MCP:

- `get_receipt_for_transition`
- `get_incoming_transition`
- `list_evidence_for_receipt`
- `list_receipts_citing_evidence`
- `list_revocations_affecting_grant`

No Console surface was added for v0.2.

## 3. Minimality review

- `kernel.py` changes are additive and read-only: the nine methods use
  `SELECT` queries and do not open Kernel write transactions.
- Existing v0.1 getters, validators, write paths, and outcome semantics were
  not modified.
- No table, column, index, migration, or schema semantic was added.
- No method infers a current/canonical State, preferred branch, grant
  validity from existence, or Evidence truth from presence.
- Pagination is bounded to 1..500, ascending only, and returns every record.
  Receipt/grant cursors use kernel-enforced sequences; other cursors use a
  stable `created_at|primary_key` walk explicitly documented as non-
  authoritative commit order. Python `isoformat()` may omit the fractional
  component when microseconds are exactly zero, which is an additional,
  extremely rare reason lexicographic `created_at` ordering must not be
  interpreted as authoritative chronology. Filtering and ordering use the
  same stored representation, so pagination remains internally consistent
  and exhaustive.
- No deferred API was smuggled into a generic dispatcher.

## 4. Executed evidence

All commands below were run with the repository `.venv` and exited 0:

- `v0_2_observability_1_focused.py`
  - All nine Kernel methods exercised.
  - Unknown/empty results, accepted/rejected/failed receipts, revoked grant
    enumeration, and branch enumeration verified.
- `v0_2_observability_2_adversarial.py`
  - Full duplicate-free paginated walks for all eight record types.
  - Double revocation preserved both rows.
  - Three-way branch fan-out returned all branches without preference.
  - Misleading opaque payloads remained inert.
- `mcp_0_1_vertical_slice.py`: PASS
- `mcp_0_2_authority_boundary.py`: PASS
- `mcp_0_3_no_direct_sqlite.py`: PASS
- `mcp_0_4_v0_2_observability.py`: PASS
  - Real MCP stdio subprocess.
  - All nine tools reached the real Kernel.
  - Failed operation Exception retrieved through MCP.
  - `None` getters verified through the `content=[]` contract.
  - Invalid `record_type` verified as a named v0.2 tool error at the
    `list_records` boundary; the shared frozen v0.1 rejection decorator
    remains `KernelError`-only.
- Relevant Kernel regressions: `authority_2`, `authority_3`, `receipt_1`,
  `receipt_2`, `exception_1`, `whole_kernel_long_history`,
  `whole_kernel_part_c`, and `whole_kernel_concurrency`: PASS.

## 5. Non-passing legacy checks and classification

The following older scripts were also executed, but are not claimed as
passing:

- `state_1_invariants.py`: failed because its shared live database already
  contains state from earlier runs; its fixed setup assumptions were no
  longer true.
- `evidence_1_lifecycle.py`: failed because its fixed authority ID already
  exists in the shared live database.
- `authority_1_standalone.py`: failed its no-State/no-Transition delta
  assertion because the shared live database changed unexpectedly during
  that run; this is outside the v0.2 read-only surface.
- `authority_2_ordering_and_scope.py`: exited 0, while its own output records
  that the live-db escalation probes are expected to reject.

These are recorded as observed outcomes, not silently converted to PASS.
The v0.2 tests themselves use throwaway database copies and passed.

## 6. Schema and repository state

`git diff main -- schema.sql` is empty. No schema file was changed.

The implementation and tests are ready for review; no merge was performed.
