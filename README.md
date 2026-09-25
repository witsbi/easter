# EASTER

**EASTER lets one AI agent pick up where another left off. It keeps the important history so the next agent can figure out what happened and what to do next.**

**I use OpenClaw/Hermes:**

1. Copy this prompt:

Go to the witsbi/easter GitHub repository, follow the installation instructions, install EASTER, and connect it to yourself as an MCP server. Ask me what identity I want to use for Genesis root authority. Do not access EASTER by importing its Python kernel directly; use the MCP interface for EASTER operations.

2. Start a fresh Hermes session.

This is necessary so Hermes loads the newly installed EASTER MCP tools.

3. Copy this prompt:

Use EASTER to establish yourself as a separate agent identity and prepare to use EASTER to keep track of our work. 

**That's it done. Then just tell the agent to use EASTER when doing work.**

**A small deterministic kernel for persistent, governed state across interchangeable AI runtimes.**

EASTER preserves authoritative history independently of the model, agent, process, or conversation currently doing the work.

The core idea is simple:

> **The intelligence is replaceable. The authoritative history is not.**

An AI runtime can disappear. A session can end. A model can change. Another runtime can continue from the durable record without requiring the original intelligence to survive.

EASTER provides a small substrate for doing that while keeping authority explicit and history append-only.

## The Six Primitives

EASTER is named for its six kernel primitives:

**E — Evidence**<br>
Immutable opaque information admitted into the historical record. Evidence may support later operations, but its presence does not establish truth, authenticity, relevance, or sufficiency.

**A — Authority**<br>
Defines who may authorize operations. Authority and State have independent lifecycles. Root authority governs Authority administration; valid grants authorize permitted kernel operations.

**S — State**<br>
An immutable opaque JSON snapshot admitted through an accepted Transition. State records what was accepted, not necessarily what is objectively true.

**T — Transition**<br>
Connects one existing State to one newly created State. Transitions create lineage. Branching is valid and expected.

**E — Exception**<br>
Immutable kernel-recorded diagnostic information describing an operation that failed to complete normally.

**R — Receipt**<br>
An immutable kernel-authored record of an operation's outcome. An `ACCEPTED` Receipt means the operation was admitted and its authoritative effects committed atomically. It does not mean the resulting State or Evidence is true or correct.

Together they form **EASTER**.

## What the Kernel Does

EASTER owns a small set of mechanics:

* append-only authoritative history
* immutable State
* explicit State transitions
* Authority and grants
* revocation
* Evidence admission and citation
* atomic operation outcomes
* Receipts
* failure diagnostics
* durable lineage

The kernel deliberately does **not** decide application meaning.

It does not determine:

* the current State
* the canonical State
* the preferred branch
* whether Evidence is true
* whether a State is correct
* what an agent should do next
* what a payload means
* which model or runtime should perform cognition

Those decisions belong to userland.

## Architecture

At its simplest:

```text
State A
   │
   │ authorized Transition
   ▼
State B
```

A State may have multiple outgoing Transitions:

```text
             ┌──▶ State B
             │
State A ─────┤
             │
             └──▶ State C
```

Both branches remain valid history.

EASTER does not silently choose one as canonical or current.

Userland decides which branch to continue.

## Authority

State answers:

> What was recorded?

Authority answers:

> Who may append what happens next?

The two are intentionally separate.

Authority administration is performed through explicit kernel operations. Grants are append-only records, and revocation affects future use without rewriting historical operations that were valid when they occurred.

An authorized actor can append history.

It cannot rewrite history through the supported kernel boundary.

## Replaceable Intelligence

EASTER does not require an agent, model, persona, conversation, or context window to be durable.

Those can all exist above the kernel.

```text
Model A ─┐
Agent B ─┼──▶ EASTER ───▶ durable authoritative history
Human C ─┤
Tool D  ─┘
```

A replacement runtime can inspect the same history and continue from it.

This makes recovery a property of the durable substrate rather than the continued existence of a particular cognitive process.

## Boundaries

EASTER guarantees its semantics through the supported kernel boundary.

The SQLite database is private kernel storage. Direct modification of SQLite is outside the kernel guarantee.

Userland should interact with EASTER through supported operations rather than writing authoritative tables directly.

Payloads are opaque JSON. Putting something inside a payload does not grant it kernel powers.

## MCP

EASTER includes an MCP server so compatible AI runtimes can interact with the kernel through a supported protocol boundary.

MCP uses **stdio**. An MCP client launches `mcp_server.py` as a child process and communicates with it through the MCP protocol.

The MCP surface exposes supported kernel operations and observational reads without adding new kernel semantics.

## Console

EASTER also includes a lightweight local Console.

The Console communicates with EASTER exclusively through MCP. It does not access SQLite directly.

It provides inspection of:

* Evidence
* Authority
* grants
* State
* Transitions
* Exceptions
* Receipts

It also exposes supported Authority operations.

The Console is observational userland. It does not determine current State, preferred branches, truth, ancestry, or other meaning that the kernel itself does not own.

The Console is currently constrained to loopback access.

## Quick Start

### 1. Clone

```bash
git clone https://github.com/witsbi/easter.git
cd easter
```

### 2. Create an environment

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements-mcp.txt
```

### 3. Initialize EASTER

Choose the identity that will hold Genesis root authority:

```bash
.venv/bin/python initialize.py data/kernel.db identity:your-root
```

Initialization creates the Genesis State, root Authority, Genesis root Grant, and `BOOTSTRAP` Receipt.

It refuses to overwrite an existing database.

### 4. Start the Console

```bash
KERNEL_DB_PATH=data/kernel.db \
CONSOLE_HOST=127.0.0.1 \
CONSOLE_PORT=8420 \
.venv/bin/python console.py
```

Wait for:

```text
Application startup complete
```

Then open:

```text
http://127.0.0.1:8420/
```

The Console launches and owns its own MCP stdio child.

## MCP Client Configuration

For normal MCP operation, configure your MCP client to launch:

```bash
.venv/bin/python mcp_server.py
```

with:

```text
KERNEL_DB_PATH=data/kernel.db
```

The client should own the MCP server process and its stdio connection.

Do not run a second standalone MCP server for the same client session.

## HTTP API

EASTER-API-0 provides a JSON/HTTP mapping of the supported MCP operations:

```text
HTTP client -> api_server.py -> MCP stdio client -> mcp_server.py -> Kernel
```

The API is a thin adapter: request bodies use the same argument names as the
MCP tools, return values retain their JSON shapes, and pagination cursors are
passed through opaquely. It does not import `kernel.py`, open SQLite, infer
current/preferred State, or add retry/deduplication behavior.

Start it against the same database configuration as MCP:

```bash
KERNEL_DB_PATH=data/kernel.db \
API_HOST=127.0.0.1 \
API_PORT=8430 \
.venv/bin/python api_server.py
```

`GET /healthz` is the readiness endpoint, and `GET /openapi.json` serves an
OpenAPI 3.0.3 description of the 19 frozen operations. API routes are under
`/v1/` and cover the ten v0.1 operations plus the nine accepted v0.2
observability operations.

Each MCP argument has exactly one HTTP representation. For example, the grant
to revoke is identified only by the URL path in
`POST /v1/grants/{grant_id}/revoke`; a `grant_id` in that request's JSON body is
rejected with `400` rather than silently reinterpreted.

**Launch contract.** The API is loopback-only until a remote authentication and
authorization design exists. The supported launch is
`.venv/bin/python api_server.py`, which refuses a non-loopback `API_HOST`. The
restriction is also enforced on every request: any client whose address is not
a loopback IP receives `403`, so launching the ASGI app directly (for example
`uvicorn api_server:app --host 0.0.0.0`) does not expose it.

## First Governed Lifecycle

A typical first lifecycle is:

```text
Genesis
   │
   ├── create actor
   │
   ├── define Authority
   │
   ├── issue Grant
   │
   ├── record Evidence
   │
   └── perform authorized Transition
            │
            ▼
         New State
            │
            ├── Transition
            └── Receipt
```

The resulting records can be inspected through MCP or the Console.

Stop the runtime and restart it using the same database.

The authoritative history remains available.

EASTER does not require the original runtime or session to recover it.

## Important Semantic Rules

**History is append-only.**<br>
Correction happens through later authorized operations, not mutation of accepted history.

**Branching is valid.**<br>
Multiple States may descend from the same State.

**There is no kernel-defined current State.**<br>
Userland chooses which branch to continue.

**Evidence is not truth.**<br>
EASTER records Evidence; it does not certify it.

**Receipts are operation outcomes.**<br>
`ACCEPTED` means the kernel admitted an operation. It does not mean the operation was wise or its payload was correct.

**Payload cannot confer authority.**<br>
Kernel powers come from kernel structures and operations, not JSON claims.

**Authority is independent of State.**<br>
Returning to an old State does not restore an Authority or Grant that has since been revoked.

## Status

EASTER currently consists of:

**Kernel v0.1** — frozen six-primitive kernel semantics.

**v0.2 observability** — MCP and Console inspection of the frozen kernel without adding new semantic authority.

The complete supported lifecycle has been exercised from a fresh clone:

```text
clone
  ↓
install
  ↓
initialize Genesis
  ↓
MCP
  ↓
create actor / Authority / Grant
  ↓
Evidence
  ↓
authorized Transition
  ↓
inspect history
  ↓
stop
  ↓
restart
  ↓
recover durable history
```

The current development rule is:

> **Attack the kernel before extending it.**

New primitives or semantic powers should not be added merely because they are convenient. A semantic change should be justified by a concrete case the existing kernel cannot naturally represent.

## Co-Creation

EASTER was developed through sustained human–AI collaboration.

**Nathan Woolen** directed the project, established its goals and acceptance boundaries, made final architectural decisions, and owns and maintains this repository.

The architecture, implementation, adversarial testing, and documentation were developed iteratively with substantial contributions from:

* **ChatGPT by OpenAI**
* **Claude by Anthropic**

Different models were used as collaborators, implementers, reviewers, and adversarial critics throughout development. Their outputs were not treated as authoritative by default; proposals were tested against the implementation, evidence, and the project's explicit human authority boundary.

This development process is part of EASTER's provenance: interchangeable intelligence contributed to building a system designed so that intelligence itself can remain interchangeable.

## Project History

EASTER emerged from experiments in AI continuity, governed state, recovery, heterogeneous model orchestration, and persistent intelligence.

Earlier designs contained substantially more machinery.

The kernel was developed largely through subtraction: concepts were removed when they could live in userland without requiring kernel ownership.

The final primitive set unexpectedly spelled:

**Evidence · Authority · State · Transition · Exception · Receipt**

**EASTER. 🪺**

The name followed the architecture, not the other way around.

## License

EASTER is released under the **MIT License**.

Copyright © 2026 Nathan Woolen.

See `LICENSE` for the full license text.
