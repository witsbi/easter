# ADR-0004: Reads are shared-world and survive grant expiry

- **Status:** Implemented (documents existing gateway behavior).
- **Date:** 2026-09-27

## Context

What happens to an agent's read access when its grant expires or is
revoked? Operators need a precise answer, not a vibe.

## Decision

The gateway re-validates grant liveness on **writes only**. Reads are
gated by token validity alone and are shared-world by design: any
authenticated token can read any state, transition, receipt, evidence,
authority, or exception record. When a grant expires, writes are rejected
but reads continue until the token itself expires (bounded by the ≤24h
TTL).

Two sharp edges, stated plainly:

1. **The trip-wire ends the grace.** If the agent attempts a write on the
   dead grant, the trip-wire kills the whole session server-side — reads
   die with it. "Reads survive expiry" holds only while the agent doesn't
   try to write.
2. **This is not record-level confidentiality.** The gateway authenticates
   callers and constrains *mutation* authority; it provides no
   tenant isolation on reads. Immediate read-cutoff for a compromised
   agent comes from token/session revocation, not grant expiry.

## Rationale

The emergent behavior is the right default: a decommissioned agent can't
act, but its history stays auditable — which is exactly when audit
matters most. Making reads die with the grant would destroy the ability
to investigate the agent you just cut off.

## Consequences

- Operators must understand that grant expiry is a *write* boundary, and
  reach for session revocation when they need a *read* boundary.
- Per-identity read scoping remains an explicit non-goal of the gateway
  (see the module docstring); if the graph ever holds material that needs
  it, that's a follow-up design, not a config change.
