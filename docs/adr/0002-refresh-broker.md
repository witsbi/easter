# ADR-0002: Operator-side refresh broker; agents never self-refresh

- **Status:** Decided, not yet implemented.
- **Date:** 2026-09-27

## Context

24-hour token TTLs without a refresh story are pure toil, and toil trains
operators into quietly lengthening TTLs until the bound is fiction.

## Decision

Refresh authority lives **on operator hardware**, not in the agents. A
small broker (cron or daemon on a machine the operator controls) holds the
minting authority and re-issues tokens on overlap cadence (12h cron, 24h
TTL). Agents hold only short-lived tokens and can never extend their own
access. The broker is the ceremony, automated.

## Rationale

A TTL only means something if refresh requires a *second* secret or a
*second* party. An agent that can refresh its own token using only the
token itself makes the TTL theater: the grant (e.g. 30 days) is the real
authority boundary, so self-refresh-until-grant-expiry has exactly the
security of a grant-length token with extra API calls. The security has to
come from somewhere — here it comes from the broker running on hardware
the operator controls.

## Consequences

- Token compromise window stays bounded at ~24h even with long-lived
  grants (ADR-0003).
- The broker is new machinery the operator must keep alive; if it dies,
  tokens expire and agents stop — fail-closed, which is the safe
  direction.
- Hosted models that cannot pull from the tokens repo still need manual
  token placement until a public tier exists.
