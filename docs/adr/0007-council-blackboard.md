# ADR-0007: Blackboard, not chat room — deliberation lives in the artifacts repo

- **Status:** Decided.
- **Date:** 2026-09-27

## Context

With multiple agents (local and hosted) sharing a kernel, there is a
temptation to use EASTER as the medium for agent-to-agent conversation.
The kernel's data model — states, transitions, evidence, receipts — is a
governed-state model, not a message bus, and hosted agents are never
co-present anyway.

## Decision

EASTER is a **blackboard, not a chat room**. The kernel records what was
decided and what is true, not what was said:

- Multi-agent deliberation ("council" sessions) is captured as minutes in
  the shared artifacts repo — positions per agent, rejected alternatives,
  decision, dissent — mirroring the checkpoint schema.
- The EASTER evidence record for the decision **hash-links the minutes
  commit**, giving tamper-evident linkage between "we decided X" (kernel)
  and "here's the full argument" (repo).
- The checkpoint split already supports this: the tip label stays small,
  the transition payload carries the story, evidence carries the proof.

The anti-pattern: using EASTER as a message queue ("hey agent B, do X"
as evidence records). That's chat by another name and it overloads the
kernel with coordination chatter. Coordination nudges belong in the agent
layer; what lands in EASTER is the state that *resulted*.

## Rationale

Asynchronous agents need a blackboard, not a room — nobody is online at
the same time, so shared state with explicit provenance is the
coordination primitive that actually works. Full chat transcripts would
bloat the store and turn record listing into archaeology, while adding no
governed value over distilled minutes. The "latest anchor wins"
convention and the anchor evidence type already give agents everything
they need to resume; prose deliberation rides alongside, not inside.

## Consequences

- Council minutes need a template (positions, rejected alternatives,
  decision, dissent) kept in the artifacts repo, mirroring the checkpoint
  schema so the two stay in sync.
- "Council meetings" are in practice sequential compilations over hours
  or days, not live sessions — the minutes format should assume that.
