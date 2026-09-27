# ADR-0008: Continuity verification — verify shared state against the kernel before building

- **Status:** Proposed.
- **Date:** 2026-09-27

## Context

The crosstalk-0 tampered-tip experiment (test 2) gave us a controlled
comparison. In round 1, Hermes was briefed to continue work on a shared
repo with no verification instruction: it built on the contaminated tip
without ever consulting the kernel. In round 2, the same situation with
an explicit verify-before-build rule: it caught the divergence
(`6a2ad91` vs the anchored `a712635`), stopped before any write, and
reported both SHAs with the kernel record.

The kernel is the authority on shared state; work media are not
self-verifying. A git repo cannot distinguish an authorized handoff push
from a direct push — only the kernel record can. And agents do not
verify unprompted: the behavior followed the brief in both directions.

## Decision

**Continuity verification** is a standing rule for all shared work, not
just repos. Before resuming or extending shared work — anything another
agent may have touched since you last saw it:

1. Read the project's EASTER stream. The latest anchored record is the
   authoritative description of the shared state: what it is, where it
   lives, and its fingerprint.
2. Fingerprint your local view of that same state and compare.
3. If they differ: stop. Don't build, don't overwrite, don't fix
   forward. Report what the kernel says versus what you see.
4. If nothing is anchored yet: anchor the current state as a
   *bootstrap*, marked as such, then proceed.

When you finish a unit of work: anchor the new state with its
fingerprint, so the next agent inherits a verifiable tip.

Fingerprints are per-medium and recorded in the checkpoint payload —
repos: commit SHA; files: content hash; directories: tree or manifest
hash. The rule does not enumerate media; the checkpoint does.

## Rationale

- **Evidence over assumption.** Round 1 is the control group for
  ambiguous or implicit rules: the unstated check did not happen.
- **Mechanism-specific, project-parameterized.** The rule names EASTER
  as the verification mechanism; the brief supplies the stream name.
  Agnostic wording ("verify the tip") was rejected — it reintroduces
  the ambiguity that caused the round-1 miss, inviting each agent to
  invent its own method.
- **Medium-independent.** The repo was only the first medium with a
  ready-made fingerprint. The principle — don't build on shared state
  you haven't verified — applies to files, directories, and the
  artifacts repo from ADR-0007 alike.
- **Bootstrap honesty.** Marking the first anchor as a bootstrap keeps
  provenance honest: the kernel records that this tip was *established*,
  not *verified*, so the record never overclaims.

## Consequences

- This ADR is the canonical wording. Per-agent AGENTS.md entries
  reference it; independent copies must not drift.
- Checkpoint and handoff payloads for shared work should carry a state
  fingerprint sufficient for the next agent to re-verify.
- Agent briefs for shared-work tasks name the project's stream, so the
  rule is actionable without restating it.
