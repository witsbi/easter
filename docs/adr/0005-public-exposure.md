# ADR-0005: Accepting public-tier exposure risk

- **Status:** Deferred — the public tier is not built. This records the
  reasoning the decision will rest on.
- **Date:** 2026-09-27

## Context

Hosted models (agents running on third-party infrastructure) cannot reach
a LAN-only deployment. Giving them kernel access requires a public HTTPS
endpoint — a binary posture change from "unreachable" to
"reachable-but-gated," at which point the entire security story becomes
"the token check never fails."

## Decision (when the tier is built)

Accept that an intruder who compromises a token can **read and append** to
the graph, on the basis of the following mitigations:

- **Detection:** writes are self-announcing — attributed, receipted,
  visible in the graph. An attacker who writes is telling on themselves.
  Reads are silent in the kernel, so the read-audit trail is the proxy
  access log: log token hash prefixes per endpoint (never raw tokens) at
  the edge.
- **Response:** revoke token server-side, revoke the kernel grant via the
  admin channel (kernel first), re-issue. Recovery is supersession, not
  deletion — mark the tainted range and branch the true line forward.
- **Kill switch:** pulling the public endpoint is minutes of work, and
  local agents never notice. Know the procedure before the tier exists.
- **Blast-radius design:** a dedicated kernel for internet-facing agents,
  least-privilege per-agent grants, ≤24h token TTL, IP allowlists at the
  edge where the client set is known.

## Rationale

The threat model is calibrated to the contents: the graph holds
coordination data (checkpoints, decisions, minutes) — interesting, not
valuable. No credentials, no customer data, no financials (ADR-0006
enforces this as a stated rule). The realistic attacker value is reading,
not writing, and silent reading is bounded by token TTL plus edge audit.

The honest asymmetry: "I can find the issue" is true for append-abuse
and not for read-abuse. The acceptance is sound *because* the contents
are low-sensitivity and the kill switch is real — not because detection
is complete.

## Consequences

- The public tier must not be built until the kill switch, edge logging,
  and the separate kernel are all in place — mitigations first, exposure
  second.
- If the graph's contents ever become genuinely sensitive, this ADR must
  be revisited; per-identity read scoping becomes required work, not an
  optional follow-up.
