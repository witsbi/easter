# ADR-0006: The kernel holds coordination, never credentials

- **Status:** Decided — a stated rule, enforced by convention and review.
- **Date:** 2026-09-27

## Context

The kernel's posture — shared-world reads (ADR-0004), attributed
append-only writes — is appropriate for some data and dangerous for
other. The threat model in ADR-0005 ("interesting, not valuable")
collapses the day secret material lands in evidence.

## Decision

**Coordination goes in the kernel; credentials never do.** Checkpoints,
decisions, anchors, minutes references — yes. API keys, tokens,
passwords, private keys, connection strings — never. Secrets live in the
vault, the tokens repo (ADR-0001), or a secrets store, and are referenced
from kernel records by hash prefix at most.

## Rationale

This is a data-classification rule, not a technical control — the kernel
cannot judge whether a payload is secret (it judges structural validity,
never wisdom). So it has to be a stated rule, not a habit: habits fail
silently when a tired operator pastes a token into an evidence record at
2am.

## Consequences

- Agent briefs and the operator guide must state this rule; reviewers
  should treat secret material in kernel records as a blocking issue.
- The rule is what keeps every other ADR's risk reasoning valid. It is
  load-bearing — say so out loud.
