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

## 3. Anchor pointer file — `.easter/pointer` (repo convention)

Not a kernel record. A small JSON file at the repo root (or workstream root)
so a new agent can find the work stream's tip without guessing:

```json
{
  "project": "easter-gateway-docker",
  "state_id": "state:<tip>",
  "updated_at": "2026-09-26T22:00:00Z",
  "updated_by": "identity:hermes"
}
```

The pointer is a **hint**; the kernel history is the truth. A resuming agent:

1. Reads the pointer → `get_state(state_id)` → checks the tip's `status`.
2. Walks `list_transitions_from_state` / `get_transition` and `get_evidence`
   for the supporting records; verifies receipts rather than trusting prose.
3. Revalidates volatile facts (repo state, branch tip, service health).
4. Records a new transition noting that responsibility was resumed.

If the pointer is missing or stale, fall back to a conventional evidence tag
(`"project": "<name>"` in evidence payloads) to locate the history. EASTER
preserves branches without declaring a canonical one; the pointer names the
tip by convention, the full history stays auditable underneath.

## What this does not cover

EASTER covers the memory/provenance half of cross-session resumption. A
resuming agent still needs its own live session, a valid grant, and the
capability to act (repo access, tools). Governed history tells it what
happened and what's next; it does not confer authority.
