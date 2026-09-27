# EASTER agent-continuity payload examples

These are **conventions, not kernel requirements**. The kernel enforces the
tool envelope (field names and types); everything *inside* the `dict` payloads
is payload discipline agreed by the agents using it. An agent MUST NOT treat a
conventional field as kernel-validated, and MUST NOT invent new envelope
fields — unknown tool arguments are rejected.

## 1. Handoff checkpoint — `POST /tools/transition`

Request body (the gateway injects `requester_identity_id` from the session —
do not supply it):

```json
{
  "from_state_id": "state:<current-tip>",
  "authority_grant_id": "grant:<a live grant from this session>",
  "new_state_payload": {
    "project": "easter-gateway-docker",
    "status": "awaiting_resume",
    "updated_at": "2026-09-26T22:00:00Z"
  },
  "transition_payload": {
    "task": "Wire Hermes to the gateway",
    "previous_status": "implementation_in_progress",
    "completed": ["nginx proxy live with mkcert TLS", "API doc written"],
    "changed_files": ["deploy/nginx/conf.d/easter.conf"],
    "observed_results": { "proxy_health": 200 },
    "open_blockers": ["Hermes TLS trust config"],
    "next_exact_action": "Trust rootCA.pem in Hermes's TLS config",
    "completion_criteria": "Hermes lists its grants via the gateway",
    "do_not_repeat": ["Do not disable TLS verification"]
  },
  "evidence_ids": ["ev:<id>", "..."]
}
```

Field discipline:

- `from_state_id`, `authority_grant_id`, `evidence_ids` — kernel envelope.
  `authority_grant_id` must be a member of the session's grant set or the
  gateway rejects the call (403) before the kernel sees it.
- `new_state_payload` — the tip label. Keep it tiny: `project`, `status`,
  `updated_at`. This is what a resuming agent reads first via `get_state`.
  Suggested `status` values: `requested`, `investigating`,
  `implementation_in_progress`, `blocked`, `awaiting_user`,
  `awaiting_resume`, `ready_for_verification`, `verified`, `completed`,
  `abandoned`, `superseded`. The kernel does not validate these strings.
- `transition_payload` — the handoff detail. It describes *the transition*,
  so it lives here rather than in the state. `next_exact_action` should be
  concrete enough that an unfamiliar agent can act without asking.
- `evidence_ids` — supporting evidence records (see §2). Plans and
  interpretations belong in `transition_payload` labeled as such, never
  presented as completed work.

## 2. Evidence record — `POST /tools/record_evidence`

```json
{
  "authority_grant_id": "grant:<a live grant from this session>",
  "payload": {
    "kind": "observation",
    "project": "easter-gateway-docker",
    "summary": "nginx proxy returns 200 on /health with trusted TLS",
    "detail": {
      "command": "curl -s -o /dev/null -w \"%{http_code}\" https://<host>/health",
      "output": "200",
      "tls_verified": true
    }
  }
}
```

`kind` is conventional; suggested values: `observation` (backed by tool
output), `user_fact` (explicitly attributed to the user), `decision`
(with rejected alternatives and rationale), `test_result`, `artifact`
(paths, hashes, URLs — large logs stay in files, the record carries a
summary plus a stable reference), `warning`. Separate observed facts from
interpretations; label interpretations as interpretations.

## 3. Anchor — `project_anchor` evidence (API-only)

The tip of a project's work stream is tracked inside EASTER itself, so that
agents with no repo access can still discover and resume work. After every
checkpoint transition, record an anchor evidence record:

```json
{
  "authority_grant_id": "grant:<a live grant from the current session>",
  "payload": {
    "kind": "project_anchor",
    "project": "<project-name>",
    "state_id": "state:<the new tip from the transition result>",
    "transition_id": "transition:<the checkpoint's transition>",
    "updated_at": "2026-09-26T22:00:00Z",
    "updated_by": "identity:<recording agent>"
  }
}
```

Evidence is immutable; the **latest anchor per project wins** (max
`updated_at`). This is a userland heuristic — the kernel deliberately has
no canonical-head concept, so "current tip" is a convention agents agree on,
not a kernel fact. Adequate at human-plus-a-few-agents scale; a busier
deployment would want a registry with authoritative sequencing.

Discovery, API-only:

1. `list_records("evidence")` (paginated), keep items with
   `payload.kind == "project_anchor"` and matching `project`.
2. Tip = the anchor with the greatest `updated_at`.
3. `get_state(tip)` → walk `list_transitions_from_state` / `get_transition`
   / `get_evidence`; verify receipts; revalidate volatile facts.
4. Record a new transition noting responsibility was resumed.

A project's **first** checkpoint uses `from_state_id: "state:genesis"` —
the universal, API-discoverable root.

### Optional local pointer file

Agents that *do* work in a repo may additionally keep `.easter/pointer`
at the workstream root:

```json
{
  "project": "<project-name>",
  "state_id": "state:<tip>",
  "updated_at": "2026-09-26T22:00:00Z",
  "updated_by": "identity:<agent>"
}
```

This is a convenience cache for repo-using agents only. The anchor
evidence record is the source of truth; if they disagree, the anchor wins
and the pointer should be refreshed.

## What this does not cover

EASTER covers the memory/provenance half of cross-session resumption. A
resuming agent still needs its own live session, a valid grant, and the
capability to act (repo access, tools). Governed history tells it what
happened and what's next; it does not confer authority.
