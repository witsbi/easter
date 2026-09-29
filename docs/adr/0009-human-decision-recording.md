# ADR-0009: Human decisions — first-party records and agent-attested records

- **Status:** Proposed.
- **Date:** 2026-09-29

## Context

The console branch (EASTER-CONSOLE-0) adds `/evidence/record`,
`/evidence/decision`, and `/transition/propose` so a human participant
can record evidence and decisions directly: human → console → MCP →
kernel → receipt. The kernel stamps the human's identity as
`caused_by_identity_id`, making the record first-party — the preserved
record is the human's own act, not an agent's representation of it.

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

1. **First-party.** Human → console → MCP → kernel. Payload convention
   `kind: "human_decision"`. The kernel stamps the human's identity as
   `caused_by_identity_id` (e.g. `identity:nathan`). This lane requires
   a grant held by that identity; the kernel's grant-ownership check
   (`_validate_grant` requires requester == grant holder) is the
   anti-impersonation boundary — an agent cannot write first-party
   records as Nathan without holding Nathan's grant, which only
   Nathan's root authority can issue.

2. **Attested.** Agent → MCP → kernel. Payload convention
   `kind: "human_decision_reported"`, naming the human in a
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
kind — the distinction is kernel-enforced, not honor-system.

## Rationale

- **Provenance fidelity.** The record must reflect the actual act
  chain. An agent recording from chat performed a different act than
  Nathan recording directly, and the kernel already knows the
  difference — this ADR just keeps the convention honest about it.
- **Attested records are visibly weaker.** Because the lane is
  kernel-stamped, no consumer can mistake an agent-reported decision
  for a first-party one, and no agent can silently upgrade its
  attestation into Nathan's signature.
- **No kernel change.** The grant-ownership boundary already exists;
  the console branch adds no bypass. The whole decision is a
  convention layered on existing primitives, which is where the
  kernel/userland boundary says it belongs.

## Consequences

- The console branch documents the first-party lane; agents recording
  Nathan's decisions from chat use the attested convention.
- Agent-side helpers for the attested payload shape are out of scope
  for this branch; a future change may add them.
- Queries, dashboards, and the Council Chamber must treat the two
  lanes differently when evidentiary weight matters.
