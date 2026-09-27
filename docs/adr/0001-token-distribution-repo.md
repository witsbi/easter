# ADR-0001: Dedicated private repository for token distribution

- **Status:** Decided, not yet implemented.
- **Date:** 2026-09-27

## Context

Short-lived agent tokens (24h TTL) need a distribution mechanism that
doesn't involve the operator hand-carrying files. The candidates were: a
folder in the existing shared artifacts repo, or a separate private repo.

## Decision

Tokens live in a **separate private repository**, not in the shared
artifacts repo. One repo, read-only deploy keys per operator-controlled
machine, the refresh broker (§4 of the operator guide) commits rotated
tokens on overlap cadence.

## Rationale

Containers follow trajectories, not just contents. The artifacts repo is
designed to be shared — its purpose and trajectory is gaining readers
(council minutes across models, collaborators, possibly public excerpts).
Tokens are designed to be restricted. Putting the restricted thing inside
the shared thing means the shared thing can never become more shared than
the tokens allow — or one day it does, and nobody remembers the tokens
folder was in there. Secrets hidden by convention instead of by boundary.

Per-agent repos were considered and rejected: the operator's agent
machines share one trust domain, and per-agent isolation already exists
where it counts — the grants. Split only when an agent lives on hardware
the operator doesn't physically control.

## Consequences

- The artifacts repo is free to grow its readership without becoming a
  token-exposure decision each time.
- One more repo and one deploy key per machine to manage — trivial cost.
- Git history accumulates expired tokens; acceptable because expiry is
  what bounds them, and old tokens are dead on arrival.
