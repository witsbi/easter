# EASTER-DOGFOOD-0 Receipt — Real Operation, Not a Synthetic Test

**Status: complete. Nathan remained root/human authority throughout;
Clawde operated under an explicit identity and root-issued Grant.**

Everything in this receipt happened against the **live project Kernel
database** (`data/kernel.db`), not a throwaway `/tmp` copy — this is
the real, permanent, append-only project history now. Every id below
is a genuine record. Before/after table counts (see "Audit" below)
reconcile exactly against the five scripts that ran.

## What happened, in order

### 1. `dogfood_0_1_bootstrap.py` — bootstrap, and an unplanned FAILED operation

The first real action attempted was creating a new `identity:clawde`
via `transition()`'s `new_identities` parameter (the only supported
identity-creation path). **It genuinely failed**:

```
receipt:b015c2db-5529-42eb-b43c-9c71725daad3, outcome=FAILED, reason="sqlite integrity failure"
```

Diagnosis required direct SQLite inspection (outside the supported
boundary, used here only for research, exactly as `MCP_0_RECEIPT.md`'s
own friction-discovery process did): `identity:clawde` already existed
— created `2026-09-19T21:22:07Z`, payload `{"name": "Clawde", "role":
"persistent_identity"}`, already holding prior grants under
`authority:clawde-scope-alpha` from earlier kernel work predating this
session's memory. This was not manufactured; it is a genuine mistake
this run made and had to diagnose, and it satisfies the brief's
"exercise ... failed operations" item organically.

Corrected: reused the existing `identity:clawde` and committed the
initial DOGFOOD-0 project State as a plain transition (no
`new_identities` needed):

```
dogfood_0_state_id=state:eb392325-a968-42c2-9503-895a1f664b6a
transition_id=transition:94dc7268-6f42-4acd-a113-e7836d7ecfd5
receipt_id=receipt:2278d097-4355-41bc-9e95-0c68a7a016e4
```

Payload (opaque userland JSON, no new Kernel semantics): `project`,
`objective`, `status`, `completed_work`, `next_action` — exactly the
fields the brief asked for, kept intentionally simple.

### 2. `dogfood_0_2_grant_clawde.py` — root issues Clawde's Grant, through the Console

Nathan/root, using **EASTER-CONSOLE-0 itself** (real HTTP server, real
HTML forms — the Console built in Phase 1 of this same work), defined
a DOGFOOD-0-scoped Authority and issued a Grant to `identity:clawde`:

```
authority_id=authority:dogfood-0-clawde
grant_id=grant:9e9de008-2301-4e39-a30f-2bbde8338bc9
define_receipt_id=receipt:9691fa57-96a5-4531-b203-b2ff100b3680
grant_receipt_id=receipt:3e4fd5cf-55ef-4e6c-8fc2-a1a24ea3393e
```

This is the "explicit identity and root-issued Grant through the
supported EASTER boundary" the brief asked for — Clawde's identity was
pre-existing, but this Grant is new and scoped specifically to this
experiment.

### 3. `dogfood_0_3_clawde_work.py` — Clawde's real work, through MCP directly

Per the brief's own architecture (`Clawde/OpenClaw -> MCP -> Kernel`,
distinct from `Nathan -> Console -> MCP -> Kernel`), Clawde talked to
MCP directly here, not through the Console. Using the Grant from step
2: retrieved the DOGFOOD-0 State, recorded genuine Evidence (the real
friction observation from step 1 — not a synthetic payload), submitted
a Transition citing that Evidence, and preserved the Receipt:

```
evidence_id=evidence:35f3e4e8-245f-45f5-8faa-fd047734bfb0
new_state_id=state:7a415aee-2ad6-44c0-983b-86296e333b22
transition_id=transition:4844b80c-bc58-4107-98d8-abf5842af769
receipt_id=receipt:ec616dc1-78cb-4c1e-9c65-e1f019f92708
```

The "real work" here is genuinely real, not a stand-in: it is this
experiment producing its own record, which is the actual DOGFOOD-0
task per the brief's "do not manufacture unnecessary complexity."

### 4. `dogfood_0_4_recovery.py` — session restart / recovery

A brand-new process (its own fresh MCP subprocess and stdio session,
no shared state with steps 1-3) retrieved the current DOGFOOD-0 State
using only a state_id it was told out-of-band (copied from step 3's
output — see the friction note below):

```
recovered_state_id=state:7a415aee-2ad6-44c0-983b-86296e333b22
status=console_and_grant_lifecycle_verified
completed_work_count=5
```

Demonstrates that the project's State outlives the session that
produced it, and a later, unrelated session can pick it back up
through the supported MCP boundary alone.

### 5. `dogfood_0_5_revoke_and_regrant.py` — revoke while MCP remains available, then re-grant

```
Tool 'transition' failed: 'Error executing tool transition: authority grant has been revoked: grant:9e9de008-2301-4e39-a30f-2bbde8338bc9 [receipt=receipt:67ebea8f-9012-4595-b63b-edc3d62bbb73]'
dogfood_0_5_revoke_and_regrant: OK
  revoke_receipt_id=receipt:75094ec6-699c-492d-b313-7872184a4046
  new_grant_id=grant:fc7b9824-e4be-4e0f-93a7-e1b9a8dbe534
  final_state_id=state:74e3073b-7f3f-46ba-9fbb-bf43d17a76d7
  final_transition_id=transition:ec5ed9bc-d141-40a0-9f0b-2c7a059b8bb4
  final_receipt_id=receipt:78a5e140-b800-41b9-b4b2-38d1295ab51d
```

Nathan/root revoked Clawde's grant through the Console (typed
confirmation, real form) → Clawde's still-connected, independent MCP
session attempted another Transition and was genuinely rejected by the
Kernel (a real `REJECTED` receipt, not staged) → Nathan/root issued a
new Grant through the Console → Clawde transitioned again,
successfully, closing the DOGFOOD-0 State at
`status: "dogfood_0_experiment_complete"`.

Branching and model/session replacement were **not** exercised: neither
arose naturally, and the brief explicitly says not to manufacture
complexity to force them. (Model/session replacement already has real
precedent elsewhere in this project's history — see `memory/2026-09-20.md`,
the Sol/Clawde Authority-Receipt handoff — so it wasn't repeated here
artificially.)

## Audit: before/after table counts

| Table | Before | After | Δ |
|---|---|---|---|
| states | 225 | 228 | +3 |
| transitions | 224 | 227 | +3 |
| receipts | 1283 | 1293 | +10 |
| exceptions | 517 | 519 | +2 |
| authority_grants | 309 | 311 | +2 |
| authority_grant_revocations | 157 | 158 | +1 |
| evidence | 18 | 19 | +1 |
| receipt_evidence | 10 | 11 | +1 |
| identities | 3 | 3 | +0 |
| authorities | 61 | 62 | +1 |

Every delta reconciles exactly against the calls made across all five
scripts (1 FAILED + 1 REJECTED + 8 ACCEPTED operations = 10 receipts;
3 ACCEPTED transitions = 3 states/transitions; 1 evidence + 1 citation;
2 new grants + 1 revocation; 1 new authority; 0 new identities since
`identity:clawde` was reused). No git-tracked file changed as a result
of running these scripts — `data/kernel.db` is gitignored.

## Friction observations (consolidated, classified)

### Observed requirement
*A real task could not be completed or reasonably understood through the supported boundary.*

1. **Diagnosing a FAILED operation.** `get_receipt` on the FAILED
   bootstrap attempt returned only `{"reason": "sqlite integrity
   failure"}` — no table, no constraint, no offending value. The real
   cause (`UNIQUE constraint failed: identities.identity_id`) exists
   only in `exceptions.payload.details`, which EASTER-MCP-0 has no
   supported method to read. This blocked root-cause diagnosis through
   the boundary alone; the fix was easy once found, but finding it
   required stepping outside the boundary this whole experiment
   otherwise respected. (Same gap `MCP_0_RECEIPT.md` already named —
   this round supplies a concrete, organically-occurring instance of
   it rather than a hypothetical.)
2. **Discovering what an identity already holds.** Before reusing
   `identity:clawde`, there was no supported way to ask "what grants
   does this identity currently hold" — `get_grant` requires already
   knowing a specific `grant_id`. The only way this run learned
   `grant:clawde-alpha` and `authority:clawde-scope-alpha` existed was
   direct SQLite inspection. Once the id was known, `get_grant`
   confirmed it fine through MCP — the block was purely in discovery,
   not confirmation.
3. **Checking for existence before creating.** The FAILED bootstrap
   attempt happened because there was no way to ask "does
   `identity:clawde` already exist" before attempting to create it —
   the only supported way to find out is to attempt the write and let
   it fail. This is the same underlying gap as #2 (no enumeration),
   but surfaced as a write-time collision rather than a read-time
   question.

### Observed inconvenience
*The task remained possible but unnecessarily difficult.*

4. **Console's control list has no identity-creation or
   transition/evidence path.** `console.py` intentionally does not
   expose `transition` or `record_evidence` (matching EASTER-CONSOLE-0's
   own brief — inspection plus Authority controls only). This wasn't
   actually hit as a live blocker in this run (identity creation was
   done via direct MCP from the start, since `CONSOLE_0_RECEIPT.md`
   already established the Console doesn't support it), but it's worth
   naming precisely: a future operator using only the Console, with no
   direct MCP access, cannot onboard a new identity or perform a
   Transition at all. The task remains fully possible through MCP
   directly — this is a Console scope choice, not a Kernel or MCP-0
   limitation.

### Hypothesis
*Something that might be useful but was not actually required during DOGFOOD-0.*

5. **A userland "last known state" pointer for recovery ergonomics.**
   Step 4's recovery only worked because the recovering process was
   told the exact `state_id` out-of-band (copied from step 3's
   output). EASTER-MCP-0 has no supported way to ask "what is the
   current/most relevant DOGFOOD-0 state" — and this is very likely
   **by design**: the Kernel deliberately has no canonical-state
   concept (`transition()`'s own docstring: "which state_id to
   continue from ... is entirely a userland decision"). A memory-side
   or receipt-side pointer (e.g., this very document) might make
   recovery more convenient for a future session, but that is
   explicitly a userland/memory concern, not a Kernel or MCP-0 gap —
   recorded as a hypothesis about surrounding tooling, not a candidate
   v0.2 Kernel API.

Findings 1-3 above extend, with concrete evidence, the two candidate
v0.2 issues already recorded in `MCP_0_RECEIPT.md` (Exception
retrieval, lineage/history inspection) and the enumeration gap
`CONSOLE_0_RECEIPT.md` first named. **No Kernel v0.2 architecture is
proposed here** — per the brief, this receipt only classifies what was
observed.

## Kernel v0.1 changes

**None.** `git diff main -- kernel.py schema.sql` is empty throughout
both CONSOLE-0 and DOGFOOD-0.

## Stop condition

DOGFOOD-0's real operation is complete: Clawde received an explicit
identity and a root-issued Grant through the supported EASTER
boundary, did genuine project work (retrieve → work → Evidence →
Transition → Receipt), demonstrated recovery through the boundary, and
exercised revoke/reject/re-grant against its own live grant — all on
the real project Kernel, all reconciled by an exact table-count audit.
Friction is recorded and classified above; no Kernel v0.2 architecture
is proposed.
