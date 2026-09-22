# Intelligence Kernel

An experimental attempt to identify the minimum primitives required for persistent, governed intelligence across interchangeable cognitive substrates.

This repository begins with a frozen architecture hypothesis. **v0.1 should be attacked rather than extended.** A semantic change or new primitive requires a counterexample that cannot be naturally represented by the frozen kernel.

## Intelligence Kernel v0.1 — FROZEN 2026-09-18

### Five candidate primitives

**STATE** — the authoritative representation currently accepted by the system. State is not necessarily objective truth; it must remain corrigible.

**IDENTITY** — persistent addressability across transformations. Identity is distinct from persona, model, process, or behavioral policy. It provides a durable referent for relationships, authority, commitments, and provenance.

**AUTHORITY** — governance over which identities may propose, accept, cause, delegate, revoke, inherit, or otherwise govern particular state transitions. Authority may originate outside the kernel. The kernel represents and enforces authority; it is not necessarily the ultimate source of authority.

**CAPABILITY** — the available means by which transformations can actually be performed. Humans, models, tools, code, councils, and other cognitive resources can supply capabilities without becoming kernel primitives themselves.

**PROVENANCE** — the justification and lineage of a transition: where it came from, what supports it, and enough linkage to reconstruct meaningful ancestry and correction.

### Fundamental graph grammar

```text
S₀ ──[ Identity · Authority · Capability · Provenance ]──▶ S₁
```

State forms the nodes. Identity, Authority, Capability, and Provenance characterize meaningful transition edges.

## Core hypothesis

> The durable object is not the intelligence performing the cognition. The durable object is the authoritative state and provenance of its transitions.

Intelligence can therefore be replaceable compute operating against a persistent substrate.

A persistent working identity may likewise be implemented independently of the cognitive resource currently participating. A model, process, conversation, or runtime can disappear while the substrate remains available for another capability to continue from authoritative state.

## What is not currently primitive

The following currently appear derivable or implementable using the five frozen primitives:

- agent
- model
- persona
- prompt
- conversation
- generic memory
- task
- goal
- context window
- tool
- workflow
- checkpoint
- steward
- council
- continuity
- branching
- promotion
- supersession
- delegation
- succession
- lineage

This list is a hypothesis, not a claim that these concepts are unimportant. They may be essential userland structures while remaining unnecessary as kernel primitives.

## Initial adversarial tests

v0.1 has so far been tested conceptually against:

- novel creation without a predetermined target state
- ambiguous intent
- conflicting valid authorities
- incorrect authoritative beliefs
- epistemic correction
- introduction of new evidence-producing capabilities
- self-modification of kernel semantics
- external authority
- delegation and revocation
- inheritance and human succession

### Novel creation

Creation can be represented as authorized generation of candidate state branches linked by provenance to prior state, followed by an authorized acceptance or rejection transition. A predetermined final state is not required.

### Conflicting authority

Conflicting valid transitions may remain unresolved. The kernel does not need to guarantee progress. Resolution can require an identity possessing authority over the conflict.

### Epistemic correction

State represents what is authoritatively accepted, not guaranteed objective truth. New evidence can justify an explicit superseding transition without rewriting the history of why the prior state was accepted.

### Kernel self-modification

A kernel transition can itself be represented as a governed branch:

```text
K₀ ──[ Identity · Authority · Capability · Provenance ]──▶ K₁
```

The kernel is not assumed to be the ultimate source of authority. An originating authority can authorize migration from K₀ to a candidate K₁ while preserving the lineage of the change.

### Authority succession

Authority can move between persistent identities without collapsing those identities:

```text
Authority(I₀, X) ──[ succession event + provenance ]──▶ Authority(I₁, X)
```

Inheritance, organizational succession, delegated AI permissions, revocation, and external authority may therefore be different graph shapes expressed by the same grammar.

## Discovery lineage

v0.1 emerged through subtraction rather than feature design.

Two earlier architecture lines were treated as fossil records:

**Cognitive OS / SynthForge** explored a control plane above intelligence: explicit promotion, bounded authority, lineage, branch/evaluate/promote behavior, and separation of accepted intent from permission to cause consequential effects.

**Threads** explored continuity above individual runtimes: durable state, structured decisions, epistemic provenance, checkpoints, explicit supersession rather than silent overwrite, and recovery independent of the intelligence that originally produced the state.

Later work with heterogeneous local and remote intelligence, capability/tool discovery, model succession, recovery, councils, routing, and state rehydration independently rediscovered several of the same pressures.

The fossil architectures are evidence sources, not ancestors that v0.1 must preserve. Implementation-specific concepts were deliberately discarded when they did not survive comparison.

## Method

The kernel emerged by attempting to delete candidate primitives.

Several concepts disappeared. Identity nearly disappeared as well, but survived in a narrower form: **persistent addressability**. Cognition may not require identity, but governance, relationships, authority transfer, commitments, and provenance across time appear to.

The working rule is therefore:

> **Attack v0.1 before extending it.**

Do not add a sixth primitive because it is useful or convenient. Add or change a primitive only when a concrete counterexample cannot be naturally expressed by the frozen five.

## Status

**FROZEN — architecture hypothesis, not implementation commitment.**

Future discoveries do not silently modify v0.1. A breaking counterexample should be recorded with its evidence and used to propose a candidate v0.2 branch.

## Fresh installation

From a fresh clone, create the SQLite database with the supported initializer
and choose the initial root identity:

```bash
python initialize.py data/kernel.db identity:your-root
```

The initializer creates Genesis, its root Authority and grant, and the
`BOOTSTRAP` Receipt atomically. It refuses to overwrite an existing path.
Start the existing Kernel/MCP boundary with `KERNEL_DB_PATH=data/kernel.db`.
