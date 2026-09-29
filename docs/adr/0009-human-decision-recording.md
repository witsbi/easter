# ADR-0009: Human decisions — first-party records and agent-attested records

- **Status:** Proposed.
- **Date:** 2026-09-29

## Context

The console branch (EASTER-CONSOLE-0) adds `/evidence/record`,
`/evidence/decision`, and `/transition/propose` so a human participant
can record evidence and decisions directly: human → console → MCP →
kernel → receipt. The kernel stamps the requester's identity as
`caused_by_identity_id`.

What the kernel proves — and what it does not: the kernel can prove
that the requester identity was `identity:nathan`, that the presented
grant was valid and held by `identity:nathan`, and that the resulting
receipt/record was stamped accordingly. The kernel does NOT
independently prove that Nathan physically submitted the console form.
If another process somehow obtained access to the console plus Nathan's
valid grant context, the kernel itself could not distinguish that
submission from Nathan clicking Submit. Establishing that the human
actually originated the request is the responsibility of the console's
deployment/authentication boundary (loopback-only; local host access is
the human-auth boundary) — not the kernel's.

Nathan may not always have console access. Agents must retain the
ability to record his decisions on his behalf (e.g. from chat). This
creates a provenance-fidelity risk: an agent-recorded "Nathan decided X"
must never be kernel-indistinguishable from Nathan's own direct
recording. If the two lanes collapse, EASTER would preserve an agent's
representation of Nathan's act while appearing to preserve Nathan's act
itself.

## Decision

Two lanes, distinguished by kernel-stamped attribution, not by payload
alone:

1. **First-party / direct.** A record is treated as first-party when
   submitted through the human console under Nathan's identity with a
   grant held by that identity: Nathan-originated console submission →
   requester/grant attribution = Nathan. Payload convention
   `kind: "human_decision"`. The kernel guarantees
   requester/grant-holder attribution (`_validate_grant` requires
   requester == grant holder); the console's
   deployment/authentication boundary is responsible for establishing
   that the human actually originated the submission. Inside EASTER,
   grant ownership remains the anti-impersonation boundary — an agent
   cannot write Nathan-attributed records through MCP without holding
   a grant issued to `identity:nathan`, which only Nathan's root
   authority can issue.

2. **Attested.** Agent records Nathan's statement → kernel attribution
   = agent → payload claims/reports Nathan as source. Payload
   convention `kind: "human_decision_reported"`, naming the human in a
   `reported_source` field and, where possible, quoting the human
   verbatim with the channel it came from. The kernel stamps the
   *agent's* identity as `caused_by_identity_id`. This is the notary
   pattern: the recorder signs her own name and attributes the words
   to the speaker. The receipt records who performed the act of
   recording; the human's identity lives in the payload as a claim,
   not a kernel fact.

The payload kinds are userland conventions; the kernel stores opaque
payloads and learns no new semantics. Consumers that need first-party
decisions filter on `caused_by_identity_id` together with the payload
kind. The kernel enforces the attribution distinction; it does not
authenticate the human hand behind a console submission — that
guarantee lives at the console's deployment boundary.

## Rationale

- **Provenance fidelity.** The record must reflect the actual act
  chain as far as each layer can see it. An agent recording from chat
  presents its own identity to the kernel; a console submission
  presents Nathan's. The kernel stamps what was presented — this ADR
  keeps the convention honest about what that stamp does and does not
  prove.
- **Attested records are visibly weaker.** Because the lane is
  kernel-stamped with the agent's identity, no consumer can mistake an
  agent-reported decision for a direct console submission — provided
  the console's deployment boundary holds. An agent that obtained
  console access plus Nathan's grant context could submit through the
  console lane; the kernel would stamp it as Nathan, and only the
  deployment boundary (not the kernel) stands in the way. Naming the
  two guarantees separately is what keeps this honest.
- **No kernel change.** The grant-ownership boundary already exists;
  the console branch adds no bypass. The whole decision is a
  convention layered on existing primitives, which is where the
  kernel/userland boundary says it belongs.

## Consequences

- The console branch documents the first-party lane; agents recording
  Nathan's decisions from chat use the attested convention.
- The console's loopback-only deployment and local-host-auth boundary
  are load-bearing for the first-party lane: they are what connects
  "requester = identity:nathan" to "Nathan the human submitted this."
  Weakening that boundary weakens the lane, and no kernel change can
  compensate — the kernel cannot see behind the presentation.
- Agent-side helpers for the attested payload shape are out of scope
  for this branch; a future change may add them.
- Queries, dashboards, and the Council Chamber must treat the two
  lanes differently when evidentiary weight matters.
