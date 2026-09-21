# EASTER Kernel v0.2 — Observability Design Review

**Status: REVIEWED. Implementation in progress for the accepted subset — see section 0.**

Sections 1-10 below are the original design review as submitted. Section 0 records the review outcome: which of the fourteen candidate methods from section 3 were actually accepted for v0.2 implementation, and which remain deferred, analyzed candidates rather than rejected designs. The rest of this document is left as originally written (including the two candidates — `list_records`'s companion single-getters and the relationship queries not accepted below) so the reasoning trail stays intact; section 0 is the authoritative statement of what actually gets built.

---

## 0. Review outcome: accepted vs. deferred

### Accepted for v0.2 implementation

1. `get_identity(identity_id)`
2. `get_authority(authority_id)`
3. `get_evidence(evidence_id)`
4. `get_transition(transition_id)`
5. `get_exception_by_receipt(receipt_id)`
6. `list_grants_for_identity(identity_id, after, limit)`
7. `list_transitions_from_state(state_id, after, limit)`
8. `list_transitions_by_grant(grant_id, after, limit)`
9. `list_records(record_type, after, limit)`

### Deferred analyzed candidates — not rejected, not yet implemented

- `get_receipt_for_transition`
- `get_incoming_transition`
- `list_evidence_for_receipt`
- `list_receipts_citing_evidence`
- `list_revocations_affecting_grant`

These five remain fully analyzed in sections 3.1-3.2 below (contracts, index support, the double-revocation finding behind `list_revocations_affecting_grant` in particular). They have not yet earned Kernel surface area through observed operational need — none is implemented in this round, and none of the implementation, tests, or MCP exposure work described in `V0_2_OBSERVABILITY_RECEIPT.md` touches them. The double-revocation finding they were partly motivated by (section 2.3) still applies to how the nine accepted methods are tested — see that receipt's adversarial section.

The rest of this document (sections 1-10) is the original review; where it describes all fourteen candidates together, section 0 above is what actually shipped.

---

## 1. DOGFOOD-0 evidence being addressed

`DOGFOOD_0_RECEIPT.md` produced nine concrete, real questions the supported boundary could not answer. Quoting the brief's own list, each is addressed by name in section 3:

1. Why did this FAILED operation fail in diagnostic detail?
2. Does a particular identity already exist?
3. What identities exist?
4. What grants does a particular identity hold?
5. What Authorities and Grants exist?
6. What States/Transitions/Receipts/Evidence/Exceptions exist?
7. What is the lineage around a particular State?
8. What operations occurred under a particular Grant?
9. What authoritative records are related to a known record?

These are treated as evidence of a real gap, not as a spec to implement literally — several of their "obvious" first-draft APIs turned out to be wrong shapes once checked against the actual schema (see section 3's per-question notes, especially Q1 and Q9).

---

## 2. Current graph / read-surface map

### 2.1 Tables, as they actually exist today (fresh read of `schema.sql`)

| Table | Primary key | Authoritative order column? | Real indexes |
|---|---|---|---|
| `identities` | `identity_id` TEXT | none (only `created_at`, wall-clock) | none |
| `authorities` | `authority_id` TEXT | none | none |
| `authority_grants` | `grant_id` TEXT | **`authority_seq`** INTEGER UNIQUE, shared sequence with revocations | `idx_authority_grants_identity`, `idx_authority_grants_authority` |
| `authority_grant_revocations` | `revocation_id` TEXT | **`authority_seq`** INTEGER UNIQUE, same shared sequence | `idx_authority_grant_revocations_grant`, `idx_authority_grant_revocations_identity` |
| `states` | `state_id` TEXT | none | none |
| `evidence` | `evidence_id` TEXT | none | none |
| `transitions` | `transition_id` TEXT | none (but see 2.2 — structural, not sequential, ordering exists) | `idx_transitions_from_state`, `idx_transitions_authority_grant`; `to_state_id` is `UNIQUE` |
| `receipt_evidence` | composite `(receipt_id, evidence_id)` | n/a (junction) | the composite PK itself (leading column `receipt_id` only) |
| `receipts` | **`receipt_seq`** INTEGER PRIMARY KEY AUTOINCREMENT | **yes — the single most reliable authoritative order in the whole schema** | `idx_receipts_operation`; no index on `transition_id` |
| `exceptions` | `exception_id` TEXT | none | none; `receipt_id` is `UNIQUE` (1:1 with receipts) |

Only two tables have a real, kernel-enforced monotonic sequence: `receipts.receipt_seq` (every operation outcome, unconditionally) and the shared `authority_seq` on `authority_grants`/`authority_grant_revocations` (deliberately decoupled from wall-clock, per the Receipt red-team fix — see `kernel.py`'s own comments on `_next_authority_seq`/`_is_grant_revoked`). Every other table has only `created_at`, a wall-clock string. This asymmetry is load-bearing for section 5.

### 2.2 The state graph is a forest rooted at genesis, not a general graph

`transitions.to_state_id` is `UNIQUE`. Since every `states` row is created either by `genesis_seed.sql` (`state:genesis` only, zero incoming transitions) or by `transition()` (which always inserts exactly one `transitions` row atomically with the `states` row it targets), **every state has either zero incoming transitions (iff it is genesis) or exactly one.** A state can be the *source* (`from_state_id`) of many transitions (a branch point — multiple children), but never the *target* of more than one. This makes the full state graph a tree rooted at `state:genesis`: ancestry (walking `to_state_id → from_state_id` backward) is always a single deterministic chain; descendants (walking `from_state_id → to_state_id` forward) can be a genuine set (multiple branches). This distinction is structural, not a policy choice, and it directly shapes the lineage design in section 3 (Q7): ancestry needs no server-side traversal at all (client-composable single hops suffice); descendant/branch enumeration is enumeration of a set, never "the" answer.

### 2.3 A genuinely new finding from this fresh read: double-revocation is not guarded

`revoke()` validates the *authorizing* root grant (`authority_grant_id`) and the last-root-grant guard, but **it never checks whether the *target* `grant_id` is already revoked before inserting a second `REVOKE` row against it.** `is_grant_revoked()` only checks "does at least one matching row exist," so a second `REVOKE` against an already-revoked grant doesn't change Authority validity — but it means `authority_grant_revocations` can structurally contain more than one `REVOKE` row for the same `grant_id`. This is exactly the kind of ambiguity the brief asks to surface rather than resolve: any new read method over this table **must** return every matching row, not assume or coerce to "the" revocation. See `list_revocations_affecting_grant` in section 3 (Q8/Q9).

### 2.4 A payload asymmetry that matters for what counts as "opaque"

`states.payload`, `evidence.payload` are caller-supplied, kernel-uninterpreted, genuinely opaque userland content — the kernel explicitly disclaims verifying, interpreting, or asserting anything about them (see `record_evidence()`'s own docstring). By contrast, `receipts.payload` for every Authority-operation and Evidence-admission receipt (`grant`/`revoke`/`revoke_all`/`define_authority`/`record_evidence`) is **entirely kernel-authored** — `action`, `grant_id`, `authority_id`, `authority_grant_id`, `caused_by_identity_id`, etc. are all constructed by `kernel.py`'s own code, never caller input. Reading a kernel-authored JSON field to answer "which grant authorized this receipt" is exposing an existing fact the kernel itself already wrote, not interpreting opaque userland meaning — a materially different, and safer, category than parsing `states.payload`. This distinction matters for Q8 in section 3.

### 2.5 What already exists in `kernel.py` today and is simply never exposed via MCP

`is_grant_revoked(grant_id) -> bool` and `validate_grant(grant_id, at_time=None, requester_identity_id=None) -> dict` are **already public Kernel methods in `main` today** — pre-dating this design review entirely. Neither is wrapped by any EASTER-MCP-0 tool (the MCP-0 tool list is `get_state`, `get_genesis_state`, `get_receipt`, `get_grant`, `define_authority`, `grant`, `revoke`, `revoke_all`, `record_evidence`, `transition` — ten tools, no `is_grant_revoked`, no `validate_grant`). This is not a new v0.2 capability at all: it's an existing MCP-0 coverage gap. See section 6.

### 2.6 An existing internal pattern that must not become a public API

`whole_kernel_long_history.py` (line 305) uses `SELECT receipt_id, outcome FROM receipts ORDER BY receipt_seq DESC LIMIT 1` — but only as a *test-verification* technique, to fetch "the receipt this specific test call just produced" in an otherwise-quiet database. This must never generalize into a public "get most recent receipt" Kernel API: across real concurrent callers, the globally-last `receipt_seq` is whichever operation happened to commit last system-wide, unrelated to any particular caller's own operation or to "current" anything. Flagged explicitly here because it is the single most concrete illustration in this codebase of "latest ≠ current."

---

## 3. Minimal proposed v0.2 read capabilities

Design principle established by the schema itself, not chosen a priori: **genericity is proposed only where the underlying tables are structurally uniform enough that a generic method doesn't just hide N per-type branches behind one name.** Single-record lookups keep per-type return-shape clarity (matching the existing, already-frozen `get_state`/`get_receipt`/`get_grant` pattern exactly, and avoiding a second, parallel way to fetch the three types MCP-0 already exposes under those exact names). Full-table enumeration is genuinely uniform across all eight primitive tables (same pagination contract, same "no filter" semantics, differing only in table/columns) — this is where a single generic method is proposed. Relationship/edge queries are schema-heterogeneous (different FK directions, different index support, some real-column, one JSON-based) and are kept as a small number of individually-named, individually-contracted methods rather than a generic edge-traversal primitive — see the explicit rejection in section 4.

**Every list method returns the shared `Page` shape and shares the shared pagination contract in section 5. Every returned record uses the exact same field shape its existing or newly-defined `get_*` counterpart uses — a list method never returns a differently-shaped record than a direct lookup of the same id would.**

### 3.1 New single-record getters (Q1, Q2, Q3-as-existence, Q6-as-lookup)

Mirror `get_state`/`get_receipt`/`get_grant` exactly: a plain `WHERE <pk> = ?` lookup, returning the full row as a dict with `payload` JSON-decoded, or `None` if absent. **Existence is answered by `result is not None` — no separate boolean "exists" method is proposed**, since that is already the established convention throughout this codebase and Console-0 already depends on it (`console_0_1_genesis_and_inspection.py` explicitly tests "unknown id comes back as an explicit null").

| Method | Contract |
|---|---|
| `get_identity(identity_id: str) -> dict \| None` | `{"identity_id", "created_at", "payload"}`. Answers Q2/Q3-as-lookup directly: `get_identity("identity:clawde") is not None` is exactly "does this identity already exist" — the real question DOGFOOD-0 hit. |
| `get_authority(authority_id: str) -> dict \| None` | `{"authority_id", "created_at", "is_root", "payload"}`. |
| `get_evidence(evidence_id: str) -> dict \| None` | `{"evidence_id", "created_at", "payload"}`. `payload` is caller-supplied opaque content — returned verbatim, never interpreted, per `record_evidence()`'s own existing disclaimer. |
| `get_transition(transition_id: str) -> dict \| None` | `{"transition_id", "from_state_id", "to_state_id", "authority_grant_id", "created_at", "payload"}`. |
| `get_exception_by_receipt(receipt_id: str) -> dict \| None` | `{"exception_id", "receipt_id", "created_at", "payload"}` where `payload` is `{"reason", "details", "unlinkable_evidence_ids"?}` exactly as `record_failure()` writes it. **Note on shape**: the "obvious" first-draft API here would be `get_exception(exception_id)`, symmetric with the other getters. That is the wrong shape — `exception_id` is generated internally by `record_failure()` and is **never returned to any caller anywhere in the existing system** (not in the `KernelError` message, not in any receipt payload). The only key a real caller will ever hold is `receipt_id` (every REJECTED/FAILED receipt's own id, which every caller already has). `exceptions.receipt_id` is `UNIQUE`, so this is a clean 1:1 lookup. This directly and completely answers Q1. |
| `get_receipt_for_transition(transition_id: str) -> dict \| None` | Same shape as `get_receipt`. `receipts.transition_id` has no `UNIQUE` constraint in `schema.sql` — uniqueness holds *by construction* across every supported write path (`transition()` always creates exactly one receipt referencing the transition_id it just minted, and `transition_id` is a fresh UUID each call), not by schema enforcement. This is documented explicitly in the contract, not silently assumed: a direct-SQL bypass (already out of scope for the whole boundary) could theoretically violate it. Needed because `transitions` rows discovered via enumeration (3.3) carry no `receipt_id` column. |

### 3.2 New relationship/edge queries (Q4, Q7, Q8, Q9)

Kept as individually-named, individually-contracted methods — the schema's relationship shapes are heterogeneous enough (different FK directions, different index support) that a generic `get_related(type, id)` dispatcher would just hide per-type branches behind one name without reducing real complexity (see section 4). **A relationship query is proposed as a new Kernel method only where the schema already has a supporting index or a real-column equality match** — a JSON-payload full-table scan is not disguised as a "paginated" Kernel primitive; see the explicit rejection of `list_receipts_by_authority_grant` in section 4.

| Method | Answers | Contract | Index support |
|---|---|---|---|
| `get_incoming_transition(state_id: str) -> dict \| None` | Q7 (ancestry, one hop) | The transition where `to_state_id = state_id`. `None` for `state:genesis` (structurally has none) and for any unknown `state_id`. At most one row, by the `UNIQUE(to_state_id)` constraint — **schema-enforced**, not merely by construction. Composing this repeatedly (state → incoming transition → `from_state_id` → `get_state` → repeat) walks the full ancestry chain back to genesis; no server-side multi-hop traversal is needed because the chain is a tree, not a general graph (section 2.2). Named for the mechanical fact (single incoming edge), not the interpreted concept ("parent"/"ancestor") — the method observes structure, it does not assert lineage meaning. | `idx_transitions_from_state` doesn't help here (this filters `to_state_id`, not `from_state_id`); the `UNIQUE(to_state_id)` constraint itself provides an implicit index. |
| `list_transitions_from_state(state_id, after=None, limit=50) -> Page` | Q7 (branches, one hop down) | Every transition with `from_state_id = state_id` — zero, one, or many. **Returns every branch, with no ordering that implies preference** (see section 5's ordering rules). Enumeration, not selection: the presence of multiple results *is* the branch-explosion fact, not a signal to resolve. | `idx_transitions_from_state` — real, existing index. |
| `list_transitions_by_grant(authority_grant_id, after=None, limit=50) -> Page` | Q8 (transitions authorized by a grant) | Every transition with `authority_grant_id = X`. | `idx_transitions_authority_grant` — real, existing index. |
| `list_grants_for_identity(identity_id, after=None, limit=50) -> Page` | Q4 | Every grant ever issued to this identity, ordered by `authority_seq` (authoritative). **Must return revoked and expired grants too, not only currently-valid ones** — filtering to "valid" would be exactly the "existence = validity" / "grant existence = currently valid authority" conflation section 6's adversarial review forbids. A caller wanting current validity calls `is_grant_revoked`/`validate_grant` (section 2.5) per `grant_id` separately — that is a distinct, existing, already-frozen v0.1 computation, not something this enumeration should fold in. | `idx_authority_grants_identity` — real, existing index. |
| `list_evidence_for_receipt(receipt_id, after=None, limit=50) -> Page` | Q9 | Every Evidence row cited in support of this receipt, via `receipt_evidence`. **Presence in this list means "was cited," never "was validated" or "is true"** — same disclaimer `record_evidence()` already states, applied here for the first time to a listing. | `receipt_evidence`'s composite PK has `receipt_id` as its leading column — well-indexed. |
| `list_receipts_citing_evidence(evidence_id, after=None, limit=50) -> Page` | Q9 | The reverse direction of the same junction. **Kept in Kernel despite `evidence_id` being the trailing (unindexed) column of the composite PK** — unlike the JSON case rejected in section 4, this is still a real-column equality match (cheap per row, not a JSON scan), and `receipt_evidence` is structurally small in this kernel's actual usage pattern (11 rows out of 1293 receipts as of the DOGFOOD-0 audit). An `idx_receipt_evidence_evidence_id` index is a genuine future `schema.sql` optimization — **not proposed here**, and not required for this method's contract to be correct today, only for it to stay cheap at much larger scale. | None today (flagged, not blocking). |
| `list_revocations_affecting_grant(grant_id, after=None, limit=50) -> Page` | Q8, Q9, and directly informed by the double-revocation finding in section 2.3 | The union of (a) every `kind='REVOKE'` row with `grant_id = X`, and (b) every `kind='REVOKE_ALL'` row with `identity_id = <X's identity_id>` and `authority_seq <= <X's authority_seq>` — exactly `_is_grant_revoked`'s own existing logic, but returning every matching row instead of collapsing to a boolean. **Must return more than one row when more than one exists** (section 2.3) rather than assuming "the" revocation. | `idx_authority_grant_revocations_grant` for (a), `idx_authority_grant_revocations_identity` plus the implicit index from `UNIQUE(authority_seq)` for the range condition in (b) — both real, existing. |

### 3.3 One generic enumeration primitive (Q3, Q5, Q6)

Unlike single-record lookups and relationship queries, full-table enumeration is **structurally identical** across all eight primitive tables: no filter, same pagination contract, differing only in which table/columns/ordering-key apply. This is the one place genericity earns its keep.

**`list_records(record_type, after=None, limit=50) -> Page`**

- `record_type: Literal["identity", "authority", "state", "transition", "receipt", "evidence", "exception", "grant"]` — one literal per primitive table (`"grant"` → `authority_grants`). Any other value is a plain input-validation error, not a Kernel semantic.
- Returns every record of that type, in the ordering rules of section 5, with `Page`'s standard shape.
- Each returned record has the **exact same shape** as calling the corresponding `get_*` method on its id — `list_records("state", ...)` items are exactly what `get_state(that_id)` would return.
- Internally this is eight private per-type queries behind one public name/one MCP tool — the genericity is in the *interface*, not a claim that the underlying tables share a real schema-level structure they don't have.
- **Deliberately does not include a ninth `"revocation"` type.** No DOGFOOD-0 question asked "what revocations exist system-wide" (only "does grant/identity X have one," already covered by 3.2's `list_revocations_affecting_grant`). Omitted for the smallest-necessary-surface goal; a candidate to add later if a real question surfaces, not now.

This directly answers Q3 (`list_records("identity", ...)`), Q5 (`list_records("authority", ...)` + `list_records("grant", ...)`), and Q6 (`list_records("state"|"transition"|"receipt"|"evidence"|"exception", ...)`) — six of the nine observed questions, with one method.

---

## 4. Explicitly rejected capabilities, and why

1. **`get_record(record_type, id)` generalizing `get_state`/`get_receipt`/`get_grant`.** Rejected for compatibility, not just taste: those three are already shipped, already MCP-0 tool names, already tested. A generic dispatcher covering them too would create two parallel ways to fetch the same three types — the kind of drift this whole project has consistently avoided (see `MCP_0_RECEIPT.md`'s own reasoning for keeping MCP-0 a literal 1:1 pass-through). New types get new named getters (section 3.1) instead, extending the existing pattern rather than replacing it.
2. **A generic `get_related(anchor_type, anchor_id, relation)` edge-traversal primitive.** Rejected per the brief's own instruction not to invent a generic graph abstraction the schema doesn't cleanly support. The relationships here have genuinely different shapes (real FK vs. junction table vs. JSON path, different index directions) — a generic dispatcher would still need a per-relation branch internally, so the "genericity" would only be a naming convenience, not a real complexity reduction, while producing a *less* precise contract per relation than section 3.2's named methods.
3. **`list_receipts_by_authority_grant(authority_grant_id, ...)`** (Authority-operation/Evidence-admission receipts filtered by the `authority_grant_id` recorded in kernel-authored `receipts.payload` JSON). Considered and dropped. `receipts.payload` has no expression index (`schema.sql` is not being modified), so this is an unindexed full-table scan regardless of whether it lives in Kernel or in MCP/userland. Wrapping an unavoidable full scan in a "paginated Kernel method" risks exactly the "hidden filtering"/"unbounded history reads" concern the brief flags, by making an O(n)-per-page operation look like a bounded primitive. **Recommendation: this belongs in MCP/userland composition** — call `list_records("receipt", ...)` (already proposed) and filter client-side on `payload.authority_grant_id`. Zero new Kernel code required. (Contrast with `list_transitions_by_grant`, kept in section 3.2 precisely because `idx_transitions_authority_grant` already makes it a real indexed query, not a scan.)
4. **Bounded multi-hop traversal** ("give me the last N ancestors," "give me the whole subtree under state X"). Rejected. Ancestry needs no server-side multi-hop support at all — it is a simple client-composable chain of single `get_incoming_transition` calls (section 2.2), and the chain has a natural, structural stopping point (`state:genesis`). Descendant/subtree traversal is rejected because it risks unbounded/combinatorial result sets, and because the Kernel would have to make an implicit ordering choice (breadth-first vs. depth-first, which branch to expand first) that is itself a form of "traversal = branch preference" — exactly the conflation section 6 forbids. `list_transitions_from_state` (one hop) composed client-side is the honest, smaller answer.
5. **A computed "is this the canonical branch" or "which branch has the most/newest history" method.** Rejected outright — would require the Kernel to hold an opinion on branch preference, explicitly forbidden.
6. **A new v0.2 revocation-status verdict** (e.g. `get_revocation_status(grant_id) -> {"revoked": bool, ...}`, bundling `list_revocations_affecting_grant`'s rows into one boolean). Not proposed as new work: `is_grant_revoked`/`validate_grant` **already exist in `kernel.py` today** (section 2.5), pre-dating this design entirely, already frozen/reviewed as part of the v0.1 Authority round. Exposing them via MCP is a smaller, separate, lower-risk decision (zero new Kernel code) — see section 6 — not part of this design's new read-surface proposal.
7. **Cross-table full-text/keyword search over opaque payloads** (`states.payload`, `evidence.payload`). Rejected outright: this would mean interpreting/indexing genuinely opaque userland content, directly crossing "what does an opaque payload mean" — explicitly forbidden. (Contrast with 3.2's `authority_grant_id` JSON reads, which are over *kernel-authored* provenance fields, not caller-supplied opaque content — see section 2.4's distinction.)
8. **New aggregate/statistical queries** beyond the two that already exist (`count_states()`, `count_transitions()`). No DOGFOOD-0 question asked for counts/grouping; adding them now would be scope creep against "smallest read-only surface necessary."

---

## 5. Ordering and pagination semantics

Applies uniformly to every `list_*`/`list_records` method proposed in section 3.

- **Return shape**: `{"items": [<record>, ...], "next_after": <opaque cursor string> | None}`. `next_after: None` means no more results exist past this page.
- **Cursor is always an opaque string a caller round-trips verbatim**, never constructs or parses. Its internal shape differs by record type (see below), which is exactly why it must be treated as opaque at the contract level.
- **Bounding**: `limit` defaults to 50, is silently clamped to `[1, 500]` regardless of what is requested. This is a resource-safety bound, not data filtering — it does not remove ambiguity from what's returned, only how much of it comes back per call. No `list_*` method has an "unlimited" mode. This directly answers the brief's "unbounded history reads" adversarial concern.
- **Direction**: ascending only, by authoritative-or-approximate append order (oldest/earliest-appended first) — **no `order: "desc"` parameter is proposed.** A `desc`/"most recent first" framing invites exactly the "give me the newest" usage the brief forbids (see section 2.6's `receipt_seq DESC LIMIT 1` example); a caller who genuinely needs recent-first can reverse client-side after paging through, at the cost of a client-side choice the Kernel itself never makes.
- **Two distinct cursor kinds, by table, and this distinction must be documented, not hidden:**
  - **Authoritative** (`receipt` → `receipt_seq`; `grant`/revocation queries → `authority_seq`): the cursor *is* that integer (stringified). Exact, monotonic, kernel-enforced, no ties possible (both columns are `UNIQUE`). This is a true commit-order key.
  - **Approximate / wall-clock** (`identity`, `authority`, `state`, `transition`, `evidence`, `exception` — every table without a dedicated sequence column): the cursor is a compound `"{created_at}|{primary_key}"` string. **This must be documented, everywhere it appears, as non-authoritative.** `created_at` is computed in Python *before* a writer's `BEGIN IMMEDIATE` acquires the write lock (see `kernel.py`'s own write methods) — under concurrent writers, wall-clock order and actual commit order can disagree, the same category of issue the Authority round's clock-skew fix already addressed for a different table. The primary-key tiebreaker guarantees pagination is *complete and duplicate-free* (no row skipped or repeated across pages even when two rows share a timestamp — genuinely observed in this project's own history, e.g. several `identity:clawde` grants created within the same millisecond during an earlier adversarial round), but it does **not** make `created_at` order equivalent to commit order, causality, or precedence. This caveat is repeated, not just stated once, everywhere a wall-clock-ordered list is exposed (MCP tool descriptions, Console page copy) — see section 9 for why this is adversarially load-bearing.

---

## 6. MCP exposure implications

Every proposed Kernel method gets exactly one MCP-0 tool of the same name and arguments, following EASTER-MCP-0's own established pattern exactly: thin pass-through, no interpretation added at the MCP layer, `KernelError` surfaced via the existing `surface_kernel_rejections` mechanism (unchanged). Fourteen new tools total: 6 getters + 7 relationship queries + 1 `list_records`. Pagination cursors pass through as opaque strings, untouched by MCP.

**Separately, and not part of this design's new surface**: `is_grant_revoked` and `validate_grant` (section 2.5) could be exposed as two more MCP tools with zero new Kernel code, since they already exist and are already frozen/reviewed. This is flagged as a distinct, smaller, lower-risk decision for whoever reviews this document to make — it is an MCP-0 coverage gap of an *existing* v0.1 capability, not a new v0.2 read primitive, and is called out here rather than silently bundled in so it gets its own explicit yes/no.

None of this requires modifying `mcp_server.py` now, per the brief — this section describes implications for a future implementation PR only.

---

## 7. Console implications

Every new `get_*`/`list_*` method gets an inspection page or a paginated browse page, following EASTER-CONSOLE-0's own established design principles exactly (no canonical/current inference, payloads shown as raw JSON, never parsed for application meaning). Specific implications worth naming now, for whoever implements later:

- A "browse" page for `list_records` (one per `record_type`) must show **every** returned record with no visual hierarchy implying preference — no "most recent" highlighting, no bold/pinned first row.
- `list_grants_for_identity`'s Console page must display revoked/expired grants **in the same list**, not hidden behind a "show all" toggle defaulted off — defaulting to a filtered view would be exactly the "hidden filtering that removes ambiguity" the brief warns against, even if the unfiltered data is technically reachable.
- Any page rendering a wall-clock-ordered list (identities, authorities, states, transitions, evidence, exceptions) must carry the same non-authoritative-ordering disclaimer from section 5 in its own page copy, not just in code comments a Console user never sees.
- `list_transitions_from_state`'s Console page, when it returns more than one result, must not lay branches out in a way that visually implies a "main" branch and "side" branches (e.g., first-listed-is-default styling) — flat, unranked presentation only.

No Console code is proposed or written here, per the brief.

---

## 8. Compatibility with frozen v0.1 semantics

- **No write path is added, changed, or removed.** Every proposed method is a `SELECT`; none opens a `self.transaction()` block, none can commit anything.
- **No validation logic changes.** `_validate_grant`, `_validate_root_grant`, `_is_grant_revoked`, `_count_other_valid_root_grants` are untouched — this design reads their *inputs and outputs* (tables), never their *logic*.
- **The four existing getters are untouched**: `get_state`, `get_genesis_state`, `get_receipt`, `get_grant` keep their exact current signatures and return shapes. Nothing in this design supersedes or wraps them.
- **`schema.sql` is unchanged.** No new table, column, or index is proposed for implementation now. Two possible *future* optimizations are named and explicitly deferred (an expression index for JSON `authority_grant_id` reads — moot, since section 4 rejects building that Kernel method at all; an index on `receipt_evidence.evidence_id` — named in section 3.2, not required for correctness today).
- **No new outcome, no new table, no new primitive.** Every proposed capability answers "what already-authoritative fact does this expose" with a concrete table/column/relationship that exists in `main` today.
- **Verified**: `git diff main -- kernel.py schema.sql mcp_server.py console.py` is empty as of this design (nothing was touched to write it).

---

## 9. Adversarial analysis

Working through the brief's own attack list against the section 3 proposal:

| Attack | Where it could sneak in | Mitigation actually adopted |
|---|---|---|
| "latest = current" | A caller sorting `list_records("state", ...)` by wall-clock and taking the last item | No `desc` ordering parameter exists (section 5) to make this the *obvious* path; every wall-clock-ordering caveat is repeated in tool/page copy, not just code comments. **Residual risk, stated honestly, not hidden**: a caller can still reverse a paginated ascending list client-side and treat the result as "latest" — no read surface can technically prevent a determined caller from doing this once ordering is exposed at all. The mitigation is documentation discipline on every surface, not a technical guarantee, and this document says so plainly rather than implying otherwise. |
| ordering = causality | Treating `created_at`-ordered enumeration as commit order | Section 5 explicitly splits authoritative (`receipt_seq`/`authority_seq`) from approximate (wall-clock+pk) cursors and documents *why* the approximate ones can disagree with true commit order (pre-lock timestamp capture), grounded in the same clock-skew category the Authority round already fixed once for a different table. |
| traversal = branch preference | `list_transitions_from_state` returning branches in an order read as "recommended path" | Ascending-only, no highlighting, no implied default (section 7's Console note); `get_incoming_transition` is single-valued *by schema constraint* (`UNIQUE(to_state_id)`), not by a choice this design makes, so no preference question can arise there at all. |
| existence = validity | `list_grants_for_identity` silently returning only currently-valid grants | Explicitly required to return revoked/expired grants too (section 3.2); validity is a separate, existing v0.1 computation (`is_grant_revoked`/`validate_grant`), never folded into the enumeration. |
| grant existence = currently valid authority | Same as above | Same mitigation. |
| Evidence existence = truth | `get_evidence`/`list_evidence_for_receipt` implying citation means verification | Both carry the same "kernel does not interpret it, verify it, or assert it is true" disclaimer `record_evidence()` already established, applied to the read side for the first time. |
| Receipt ACCEPTED = semantic correctness | `list_records("receipt", ...)` or `get_receipt_for_transition` treating `outcome` as a quality signal | `outcome` is returned verbatim, exactly as `get_receipt` already does today; no proposed method filters, sorts by, or highlights outcome. |
| Exception details = authoritative explanation of external reality | `get_exception_by_receipt` presenting `details` as ground truth | `details` is returned exactly as caller/exception-supplied diagnostic content, with the same category of disclaimer Evidence already carries — this is a genuinely new disclaimer for this project (Exception detail was never read-exposed before), applied here for the first time, deliberately, not assumed. |
| payload-derived Kernel behavior | The one JSON read this design does propose (none, after section 4's rejection of `list_receipts_by_authority_grant`) | Resolved by rejection, not mitigation: no proposed method branches Kernel *behavior* on payload content. The kernel-authored-vs-caller-supplied JSON distinction (section 2.4) is what makes even the rejected candidate safe in principle — it was dropped for an indexing/scope reason, not a safety one. |
| unbounded history reads | Any `list_*` call with no limit | Every method shares one bounding rule: default 50, hard-clamped max 500, no unlimited mode (section 5). |
| hidden filtering that removes ambiguity | A Console default view, or a Kernel default, quietly excluding revoked/rejected/non-preferred records | Section 3.2 and section 7 both require full, unfiltered results as the *only* mode — no default-filtered view is proposed anywhere, at either layer. |

**Two findings from this pass that were not anticipated before writing this document:**
1. Section 2.3's double-revocation gap — discovered only by re-reading `revoke()` line-by-line against the "do not assume the first obvious API is correct" instruction, not from any DOGFOOD-0 observation. It directly shaped `list_revocations_affecting_grant`'s contract (must return N rows, not assume one).
2. Section 2.6's `receipt_seq DESC LIMIT 1` pattern already living in the test suite as an internal convenience — a concrete, in-repo illustration of exactly the "latest = current" trap this design has to avoid generalizing into a public API.

---

## 10. Smallest proposed implementation/test plan (for a future PR — not this one)

Not implemented now, per the brief. Sized here only to support the "smallest necessary surface" judgment:

- **Kernel**: 14 new read-only methods on `Kernel` (6 single getters, 7 relationship queries, 1 generic `list_records`), zero new tables/columns/indexes, zero changes to any existing method.
- **MCP-0**: 14 new tools, same names/arguments, following `surface_kernel_rejections`'s existing pattern (though these are pure reads with no `KernelError` path expected in the success case — input-validation errors, e.g. an unknown `record_type`, would still route through it).
- **Console-0**: one inspection page per new getter, one paginated browse page per relationship/enumeration method, all following the disclaimers in section 7.
- **Tests**: mirroring the existing `kernel_*`/`mcp_0_*`/`console_0_*` conventions — a regression script per method proving (a) the exact fact it exposes matches direct db inspection, (b) pagination is complete and duplicate-free across a multi-page walk, (c) an empty/unknown id or type returns `None`/empty page rather than an error, and — specifically informed by section 2.3 — (d) a test that induces a real double-`REVOKE` and asserts `list_revocations_affecting_grant` returns both rows, not one.

---

## Conclusion: does anything here require a new semantic primitive?

**No.** Every capability proposed in section 3 is pure exposure of an already-authoritative fact through a table, column, or relationship that exists in `main` today — no new outcome, no new table, no new write path, no new validation rule. The one adjacent capability that looks close to "new semantics" — a computed grant-revocation verdict — already exists in v0.1 (`is_grant_revoked`/`validate_grant`, section 2.5) and simply lacks MCP exposure; that is a smaller, separate, already-low-risk decision, not a new Kernel primitive, and is named explicitly in section 6 so it can be decided on its own rather than folded silently into this design.
