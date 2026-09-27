# ADR-0003: Long-lived grants with short-lived tokens

- **Status:** Decided; revocation-timeliness verification pending.
- **Date:** 2026-09-27

## Context

With the refresh broker (ADR-0002) removing token toil, the question is
what the grant lifetime should be. Short grants re-introduce ceremony
toil; long grants concentrate authority.

## Decision

Grants are **long-lived** (e.g. 30 days). The grant is the durable
*authorization decision* ("this agent may do X"); the token is short-lived
*proof* that rotates underneath it.

## Rationale

Splitting durability from proof gets both properties: the operator makes
the authorization decision rarely (no toil), while the compromise window
for a stolen credential stays at the token TTL. This is the standard
shape, and it matches the kernel's own semantics — the kernel already
distinguishes "authority is live" (grant window) from "caller is
authenticated" (session).

## Consequences

- Long-lived grants shift the entire security burden onto **revocation
  working promptly**. When a grant is revoked, outstanding tokens must die
  immediately, not at next mint. The gateway re-checks grant liveness on
  writes and the trip-wire kills the session on a rejected write; the
  pending verification is that no read or write path honors a token whose
  grant has died.
- Grant issuance stays a deliberate human ceremony; grant *renewal* should
  be rare enough to stay deliberate.
