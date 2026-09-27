# EASTER Operator Guide

How to deploy EASTER, run the identity ceremony, distribute tokens, and
operate a multi-agent kernel. This guide documents the **pattern**, not any
particular instance: hostnames, LAN layouts, and cadences below are
placeholders (`<...>`) for the operator to fill in. Never commit
instance specifics to this repo.

Status legend used throughout:

- **Implemented** — in the repo, tested.
- **Decided** — architecture agreed, not yet built.
- **Deferred** — deliberately not done yet; the decision is recorded.

## The stack

EASTER deployments have five layers, built on different days for different
reasons. Understand them in order; do not try to absorb the system top-down.

1. **Kernel** (`kernel.py`, `schema.sql`) — append-only governed state:
   identities, grants, states, transitions, evidence, receipts, exceptions.
   Judges structural validity and whether authority is live. Never judges
   wisdom or intent. Untouched by deployments.
2. **Gateway** (`gateway.py`) — the userland auth layer. Authenticated
   HTTPS (`POST /tools/{tool}`), Bearer tokens, session binding, grant
   liveness re-checks on writes, the trip-wire. Auth, sessions, transport,
   and read confidentiality live here, never in the kernel.
3. **Transport** — how the gateway is reached: loopback, LAN TLS proxy, or
   public. See §2.
4. **Ceremony** — the human ritual: bootstrapping identities, issuing
   grants, minting tokens. Host access *is* human authentication; there is
   no human-auth code path in the gateway.
5. **Conventions** — the agent-side discipline that makes the kernel
   useful: project anchors, checkpoint splits, the blackboard rule. See
   `docs/agent-continuity-payloads.md` and §6.

## 1. Deploy

**Implemented.** The Docker deployment lives in `deploy/`. The gateway
container serves the kernel over loopback inside the container; nothing in
the deployment listens on anything but `127.0.0.1` by default. Network
services ship loopback-only until real TLS and host hardening are
explicitly in place — that deferral is stated, not accidental.

```bash
# from the repo root
docker compose -f deploy/docker-compose.yml up -d --build
```

Persistence lives in the container's Docker volume. Back it up like any
database; the kernel is append-only, so point-in-time copies are always
consistent.

## 2. Transport tiers

Pick exactly one. Each tier is a deliberate posture change, not just a
config tweak.

### Tier 0 — Loopback (default)

The gateway is reachable only from its own host. Single-machine agents,
local testing. This is where every deployment starts and where it stays
until you decide otherwise.

### Tier 1 — LAN via TLS proxy

**Implemented pattern.** A reverse proxy (e.g. nginx in Docker) terminates
TLS with a private CA (e.g. mkcert) and forwards to the gateway's
loopback port. Agents on the LAN trust the private CA root.

Rules:

- The gateway itself stays loopback-bound. The proxy is the only new
  listener.
- Never distribute the CA **private key**. Distribute the root cert only,
  through a channel you control.
- Some runtimes ignore the OS trust store (Node.js is the classic case)
  and need the CA pointed at explicitly
  (e.g. `NODE_EXTRA_CA_CERTS=<path-to-rootCA.pem>`).

### Tier 2 — Public (deferred)

A public HTTPS endpoint (e.g. behind a managed API gateway, possibly with
an API→MCP translation layer) so hosted models can reach the kernel.
**This is a binary posture change**: today the risk is ~zero because
nothing is reachable; the moment it is public, the entire security story
becomes "the token check never fails."

Before doing this, have answers for:

- **Backend reachability.** A managed gateway cannot call back to a host
  behind home NAT. You need a port forward (a hole in the NAT),
  a tunnel, or the gateway hosted in cloud infra. That prerequisite is
  itself an exposure decision.
- **TLS behind the edge.** Keep TLS on the hop behind the edge
  terminator; an internal plaintext hop is the gap everyone forgets.
- **Auth passthrough.** The `Authorization: Bearer` header must reach your
  gateway unmangled — the ceremony survives, the edge only adds its own
  gating (API keys, IP allowlists).
- **Separate kernel.** Consider a dedicated kernel for internet-facing
  agents, distinct from the private one. One kernel per domain: the worst
  case is then bounded to a database you chose to expose.
- **The kill switch.** Know in advance how you pull the public endpoint.
  It should be minutes of work, and local agents should never notice.

See ADR-0005 for the full risk acceptance reasoning.

## 3. The ceremony

**Implemented.** There is no human-auth code path in the gateway.
The operator mints and revokes by running the module locally over the
admin channel (loopback):

```bash
python gateway.py mint --identity <id> --grants <grant-ids> --ttl 24h
python gateway.py list        # token hash prefixes, never raw tokens
python gateway.py revoke <token-or-unambiguous-prefix>
```

Ceremony checklist per agent:

1. Create `identity:<agent>` (kernel `define_authority` lineage, or the
   gateway's bootstrap flow).
2. Issue a least-privilege grant scoped to the agent's projects.
   Prefer long-lived grants (e.g. 30 days) — see ADR-0003.
3. Mint a short-lived agent token (max 24h TTL).
4. Hand the token to the agent through a secure channel: a `0600` file
   on a machine you control, a password manager, a secrets store.
   **Never chat, never the kernel, never the artifacts repo.**

Token hygiene is non-negotiable: chat is not end-to-end encrypted and
pasted secrets live in history; the kernel is shared-world readable
(ADR-0004).

## 4. Token lifecycle

**Decided, not yet implemented.** Short TTLs without a refresh story are
just toil, and toil trains operators out of the posture. But an agent that
can refresh its own token with only the token itself makes the TTL
theater — the grant is the real authority boundary, so self-refresh has
exactly the security of a grant-length token with extra API calls.
Refresh must require a second secret or a second party.

The decided design:

- **Minting authority stays on operator hardware.** A small broker
  (cron or daemon on a machine you control) holds the authority to mint.
  Agents hold only short-lived tokens and can never extend their own
  access. The broker is the ceremony, automated.
- **Distribution via a dedicated private tokens repo** (ADR-0001):
  one repo, read-only deploy keys per machine, the broker commits fresh
  tokens. Kept separate from the artifacts repo — containers follow
  trajectories, and the artifacts repo is built to gain readers.
- **Overlap rotation:** cron every 12h minting 24h tokens, so a valid
  token is always present even if a run fails or an agent reads
  mid-rotation.
- **Grants are long-lived** (ADR-0003). The grant is the durable
  authorization decision; the token is short-lived proof.

## 5. Onboarding agents

One identity per agent, one least-privilege grant per agent, one token at
a time. Give each agent a short standalone brief: how to reach the
gateway, which project streams exist, the anchor/checkpoint conventions
from `docs/agent-continuity-payloads.md`, and the rules in §6 and §8.

Agents that cannot reach the network path you chose cannot use the
kernel — there is no fallback. (E.g. a cloud VM behind an HTTP egress
proxy cannot join a LAN-only deployment over VPN; plan the tier for the
agents you actually have.)

## 6. Operating conventions

- **A project is a named workstream.** Its first checkpoint branches from
  `state:genesis`.
- **Checkpoints split small tip / full story:** `new_state_payload` is a
  small tip label; `transition_payload` carries completed work, blockers,
  exact next action, completion criteria, hazards; `evidence_ids` link
  immutable supporting facts.
- **Discovery is API-only.** The canonical anchor is a `project_anchor`
  evidence record in the kernel, found by paginated `list_records`
  filtered on `payload.kind == "project_anchor"` and `payload.project`.
  Latest anchor wins is a userland convention; the kernel has no
  canonical-head concept.
- **Blackboard, not chat room** (ADR-0007). The kernel records what was
  decided and what is true, not what was said. Multi-agent deliberation
  lives in the artifacts repo as council minutes; EASTER evidence
  hash-links the minutes commit.
- **If branches conflict, escalate to the operator.** Never guess.
- **Never blindly retry a timed-out transition.** The kernel has no
  deduplication; a retry may create a second valid branch.

## 7. Incident response

- **Suspected token compromise:** revoke the token server-side
  (`revoke`), revoke the kernel grant via the admin channel (kernel
  first), then re-issue. The trip-wire bounds a dead grant's fallout to a
  single receipt; every later attempt 401s/403s at the gateway.
- **Suspected read abuse:** reads are silent in the kernel. Your
  read-audit trail is the proxy access log — log token hash prefixes per
  endpoint (never raw tokens) at the edge.
- **Public tier:** pull the endpoint (the kill switch from §2). Local
  agents are unaffected.
- **Recovery is supersession, not deletion.** Mark the tainted range with
  a new transition and branch the true line forward. The scar stays
  visible; decisions are never overwritten, only superseded.

## 8. What stays out of the kernel

The kernel holds **coordination, never credentials** (ADR-0006):
checkpoints, decisions, anchors, minutes references — yes. API keys,
tokens, passwords, private keys — never; those live in the vault, the
tokens repo, or a secrets store, referenced by hash prefix at most.
The kernel's posture (shared-world reads, attributed writes) is
appropriate for coordination data and *not* for secrets. The day
something secret lands in evidence, the posture silently changes — so
this is a stated rule, not a habit.
