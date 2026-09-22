# EASTER-CONSOLE-0 Receipt — Human Control Surface over MCP-0

**Status: implemented, tested, verified. Proceeding to DOGFOOD-0.**

## What was implemented

`console.py` — a local web UI (Starlette + Uvicorn, both already
transitive dependencies of the installed `mcp` SDK, so no new
third-party package was added) that talks to the Kernel **exclusively
through EASTER-MCP-0**:

```
Nathan -> Console -> MCP -> Kernel
Clawde/OpenClaw -> MCP -> Kernel
```

On startup, the Console spawns `mcp_server.py` as a real subprocess
over stdio and holds one long-lived `mcp.ClientSession` for its entire
lifetime. Every control the Console offers is a thin HTML form around
exactly one MCP-0 tool call — the Console never talks to `kernel.py`
or SQLite.

### Controls provided (all from EASTER-MCP-0's existing supported operations)

| Route | MCP-0 tool |
|---|---|
| `GET /state/genesis` | `get_genesis_state` |
| `GET /state?state_id=...` | `get_state` |
| `GET /receipt?receipt_id=...` | `get_receipt` |
| `GET /grant?grant_id=...` | `get_grant` |
| `GET`/`POST /authority/define` | `define_authority` |
| `GET`/`POST /grant/issue` | `grant` |
| `GET`/`POST /grant/revoke` | `revoke` |
| `GET`/`POST /grant/revoke-all` | `revoke_all` |

Every write form asks the operator to name `requester_identity_id` and
`authority_grant_id` explicitly — the Console never hardcodes or
assumes "the operator is root." Whether a presented grant is actually
valid and root is entirely the Kernel's decision, exactly as it is for
any other MCP caller. Payloads are shown as raw JSON text, never
parsed for application-level fields — the Console does not interpret
State/Receipt/Grant payload content as Kernel semantics, and it never
infers or displays a "current"/"canonical" State or branch.

### Destructive-action gate

`revoke` and `revoke_all` require the operator to **re-type the exact
target id** (`grant_id` / `identity_id`) into a second confirmation
field. A mismatch — including an empty confirmation — is rejected by
the Console itself before any MCP call is made; the page says so
explicitly and no Kernel state changes. This is a userland safety
gate, not a Kernel rule, and it applies uniformly to every caller of
those two forms (there is no separate ungated path — see "design
change during implementation" below).

### Design change made during implementation

The first draft also exposed a generic `POST /api/{tool_name}` JSON
passthrough for scripting/testing convenience. It was removed before
finishing: it bypassed the typed-confirmation gate on `revoke`/
`revoke_all`, which directly contradicts the brief's "revocation
should require deliberate human action rather than happening
implicitly," and it wasn't one of the eight requested controls. All
Console-0 tests instead drive the real HTML forms (`POST`,
url-encoded, exactly what a browser sends), which is also stronger
runtime evidence — it's the actual code path a human operator would
exercise, not a side channel.

## Runtime evidence

Four executable scripts (no pytest, matching this repo's existing
convention), each launching **both** `console.py` (real HTTP server on
a free `127.0.0.1` port) **and**, transitively, `mcp_server.py` (real
subprocess over stdio) against a throwaway `/tmp` copy of
`data/kernel.db`. All HTTP calls are real `http.client` requests, not
in-process function calls or a test client.

### `console_0_1_genesis_and_inspection.py` — verification 1 & 2

Seeds one real State/Evidence/Transition/Receipt via a separate direct
MCP client (Console-0 does not expose `transition`/`record_evidence`
as controls — inspection only, per the brief's control list), then
confirms the Console can retrieve Genesis and inspect that known
State/Receipt, plus the Genesis root Grant. Also confirms an unknown
id comes back as an explicit `null`, not a crash or an invented
"not found" concept.

```
console_0_1_genesis_and_inspection: OK
  state_id=state:795a07cf-4f07-4051-b579-01a08dcbf641
  receipt_id=receipt:7de3fdee-f90f-4b8c-a1ad-fff64a5789b2
```

### `console_0_2_grant_lifecycle.py` — verification 3, 4, 5, 6

```
Tool 'transition' failed: 'Error executing tool transition: authority grant has been revoked: grant:2499e465-f302-477b-b8be-720fec81f8e7 [receipt=receipt:ac36ce2a-9faf-484b-b6ff-8ec7b67d210d]'
console_0_2_grant_lifecycle: OK
  authority_id=authority:console-0-grant-lifecycle-op
  first_grant_id=grant:2499e465-f302-477b-b8be-720fec81f8e7 (issued, exercised, revoked, then rejected)
  second_grant_id=grant:191b7302-2aec-47b4-9237-17225b46a0e9 (issued again, exercised successfully)
```

Console issues a real Grant (3) and revokes it (4) through its real
HTML forms; a *separate* MCP client (its own subprocess, its own
session — representing an independent agent) exercises that grant
before and after revocation to show (5) the revoked grant's holder
remains MCP-connected and the call transports normally, but the
Kernel rejects it with its own `AuthorityError` text, and (6) a newly
Console-issued Grant restores the ability to transition.

### `console_0_3_confirmation_gate.py` — destructive-action safety

```
console_0_3_confirmation_gate: OK
  grant_id=grant:3cbe83c4-a58c-485b-b043-51c592451590 (mismatched confirmation rejected twice, then revoked on exact match)
```

Proves a mismatched or empty confirmation is rejected by the Console
before any MCP call — the target grant is confirmed still valid
afterward via a follow-up inspection — and that an exact match
proceeds to a real Kernel revocation. Repeats the same check for
`revoke_all`.

### `console_0_4_no_direct_kernel_access.py` — verification 7

Static AST check of `console.py`'s own source: no `sqlite3` import, no
`kernel` import at all (the Console holds no `Kernel` object — unlike
`mcp_server.py`, it doesn't even need `KernelError`), no
`.execute(`/`.cursor(`/`.connect(` calls, no string literal naming a
`.db` file, and confirms the module does reference `mcp_server.py` as
the subprocess it spawns (the only path to the Kernel).

```
console_0_4_no_direct_kernel_access: OK
  top-level imports: ['__future__', 'contextlib', 'html', 'json', 'mcp', 'os', 'pathlib', 'starlette', 'sys', 'typing', 'uvicorn']
```

All four scripts were run consecutively immediately before writing
this receipt; results above are from that run. No leftover Console or
MCP-server processes remained afterward.

## Known observability limitations (not worked around)

Per the brief, these are recorded as unanswerable questions, not
converted into a proposed API or a Kernel change:

- **"Which Exceptions have been recorded, and why did a given failed
  operation fail in diagnostic detail?"** — MCP-0 has no
  `get_exception`, so the Console has no page for this. A human using
  only the Console sees a Kernel rejection's `reason` text (via the
  `ToolError` surfaced from a failed write) but never the structured
  `exceptions.payload` diagnostic detail.
- **"What is the full lineage of a given State, or what transitions
  were performed under a given Grant?"** — MCP-0 has no lineage/
  history traversal, so the Console cannot render an ancestry view or
  a "transitions by grant" view. An operator can only look up a State/
  Receipt/Grant if they already know its id from somewhere else.
- **"What is the complete current graph — all States, Grants, and
  Authorities in the system?"** — MCP-0 has no enumeration/listing
  operation of any kind (every getter takes a specific id). The
  Console's home page is a fixed list of controls, not a live
  directory, for exactly this reason.

These match and extend the two candidate v0.2 issues already recorded
in `MCP_0_RECEIPT.md` (Exception retrieval, lineage/history
inspection), plus a third one this round surfaced on its own:
**enumeration/listing** — MCP-0 has no way to ask "what exists" at
all, only "what is this specific id." Not implemented here.

## Kernel v0.1 changes

**None.** `git diff main -- kernel.py schema.sql` is empty. `console.py`
never imports `kernel.py`.

## Addendum: PR #13 review fixes

PR review on this work found two issues, both fixed on the same
branch without touching `kernel.py`/`schema.sql`:

1. **Typed confirmation is not a security boundary.** The re-type
   confirmation on `revoke`/`revoke_all` guards against an operator's
   own mistake — it does nothing to stop a malicious cross-origin page
   from submitting a matching hidden form to the Console on the
   operator's behalf (the attacker's page can just fill in the same
   value twice). Fixed with two independent, additive changes, both
   entirely in `console.py`:
   - **Loopback-only, enforced, not just defaulted.** `CONSOLE_HOST`
     already defaulted to `127.0.0.1`, but any value was previously
     accepted. Startup now refuses to bind to anything outside
     `{127.0.0.1, localhost, ::1}` with a clear error, since there is
     no authentication or remote-access security design yet.
   - **Origin/Referer check on every authority-changing POST**
     (`reject_cross_origin`, applied to `define_authority_submit`,
     `grant_issue_submit`, `grant_revoke_submit`, `revoke_all_submit`).
     A request whose `Origin` (or, when absent, `Referer`) header does
     not match the Console's own loopback origin is rejected with 403
     *before* any MCP call — verified in `console_0_5_csrf_origin_protection.py`
     by taking a direct sqlite table count immediately before and
     after each cross-origin attempt on all four routes and asserting
     it is unchanged. A request with neither header (first-party
     tooling: curl, this repo's own test scripts) is treated as
     legitimate, since real browsers reliably attach `Origin` to
     cross-origin state-changing requests. No authentication semantics
     were added anywhere, and none live in the Kernel.
2. **Malformed JSON in the free-text `payload` field crashed with a
   bare HTTP 500.** `define_authority_submit` now catches
   `json.JSONDecodeError` and re-renders the form with an actionable
   400 error instead of letting it propagate — fixed and covered by
   `console_0_6_malformed_json_payload.py`.

All six Console-0 tests (four original plus these two) and all three
MCP-0 tests were rerun after the fix; all pass. `git diff main --
kernel.py schema.sql` remains empty.

## Stop condition

All seven numbered verification points plus the destructive-action
confirmation gate pass with real runtime evidence (real HTTP server,
real MCP subprocess, real Kernel db). Proceeding to EASTER-DOGFOOD-0.
