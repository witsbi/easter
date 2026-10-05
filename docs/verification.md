# Supported verification suite

## Clean-clone command

From the repository root, run:

```bash
PYTHON_BIN=python3.14 ./scripts/run-supported-verification.sh
```

`PYTHON_BIN` may be omitted when `python3` is CPython 3.14.

The command creates a temporary exported copy of the current Git `HEAD`, creates a temporary virtual environment, installs `requirements-mcp.txt` and `requirements-verification.txt`, creates a fresh isolated database for every verification script, and removes the entire temporary workspace on exit. It does not read or modify `data/kernel.db` in the caller's checkout.

Success is exactly:

```text
RESULT: PASS (35/35 scripts)
```

Any dependency, fixture, timeout, or assertion failure exits nonzero and identifies the failing script. The configured count is checked by the harness itself, so adding or removing a supported script requires deliberately updating the expected count.

## Supported environment

The supported artifact-verification environment is:

- CPython 3.14;
- the dependencies installed from `requirements-mcp.txt` (`mcp==2.2.0` at this revision, which transitively resolves starlette/uvicorn) and `requirements-verification.txt` (`cryptography==50.0.2`, `keyring==25.7.0`, added 2026-10-05 for the token-broker tests);
- a `sqlite3` command-line client available on `PATH`;
- SQLite with foreign-key, JSON1/`json_valid`, window-function, trigger, and `RETURNING` support;
- loopback socket binding for the HTTP API, Console, and token-broker checks;
- outbound-proxy isolation for the harness's spawned subprocesses (`NO_PROXY=*`/`no_proxy=*`, set by `run_checked()` in `run_supported_suite.py`): an ambient `HTTP_PROXY`/`HTTPS_PROXY` without a loopback bypass otherwise intercepts a test's own `127.0.0.1` probes;
- Git and `tar`, used to export the exact committed tree into the isolated workspace.

The remediation was exercised with CPython 3.14.7, Python's SQLite 3.53.4 binding, and SQLite CLI 3.51.0 on macOS. The suite does not require Docker, an EASTER gateway, credentials, an existing ledger, or developer-local record IDs. The OS keychain used by `keyring` may be absent in some environments (e.g. a headless Linux container with no Secret Service/KWallet); the broker falls back to a chmod-600 file in that case, and `tests/broker_1_mint_rotate_revoke.py` passes either way.

## Current suite boundary

The 35-script supported suite covers:

- harness enforcement that assertion-based tests cannot run under optimized Python;
- fresh initialization and refusal to overwrite;
- Authority ordering, scope, and root-model checks using generated isolated prerequisites;
- Receipt minimality and one-operation/one-terminal-Receipt cardinality, including the PR #31 regression;
- State, Evidence, Exception, atomicity, concurrency, branching, and whole-kernel composition checks;
- MCP v0.1/v0.2 boundaries;
- HTTP API mapping, security, pagination, OpenAPI, launch, and argument-shape checks;
- Console inspection, Authority operations, confirmation, CSRF, malformed-input, observability, and human-participant checks;
- focused v0.2 observability behavior;
- EASTER Enterprise token broker: Ed25519 mint/rotate/revoke, key-rotation overlap, signature/claim/expiry/TTL-cap rejection, private-key-never-logged, and EASTER Evidence lineage for every broker action, verified against the real kernel's own records, not the broker's self-report;
- EASTER Enterprise token broker, Evidence-ordering safety and input hardening (added 2026-10-05 after independent review of PR #35): mint, revoke-token, and rotate-key each force a real kernel Evidence-write rejection (a nonexistent `authority_grant_id`, not a mock) and assert directly against the broker's own `issuance.db` that no row was created and no existing row was mutated -- the durable broker-side effect and the canonical kernel accountability record can never diverge, because the broker-side write never happens until the kernel write has already succeeded; revoke-token is additionally idempotent, returning `already_revoked: true` with no second Evidence write when a token is revoked twice; the v1 token role is pinned to `"agent"` and any other value is rejected with a 400, not silently coerced or ignored; `ttl_seconds` is validated end to end (non-integer, non-positive, and the 24h policy-cap boundary and over-cap cases) with a clean 400 rather than an unhandled exception;
- gateway dual token path: the pre-existing opaque `SessionStore` path is unchanged and continues to work; a parallel Ed25519 path (unknown/revoked/expired/tampered/malformed/bad-role rejection, rotation overlap, the issuance-outage failure mode, and the authority trip-wire) is admitted alongside it via a read-only `broker/reader.py` view of the broker's `issuance.db`, preserving the gateway's structural no-kernel-sqlite/no-kernel-import boundary (the trip-wire for a signed token is process-local, not the broker's own persistent denylist -- see `gateway.py`'s module docstring for that known gap).

Every script receives a newly initialized database. The two current Authority scripts also receive an isolated `identity:clawde` and `authority:clawde-scope-alpha` fixture created through supported kernel operations. No generated identifier is copied from another test or a developer ledger.

## Historical and non-suite boundary

The repository deliberately preserves scripts that are not in the current supported suite:

- `authority_0a.py`, `authority_0b_0f.py`, `authority_1_standalone.py`, and `receipt_1_remediation.py` are historical staged experiments/remediation evidence with sequencing or historical-fixture assumptions.
- `dogfood_0_*.py` is an ordered historical dogfood ceremony, not an isolated regression suite.
- `v0_2_observability_2_adversarial.py` contains development-ledger corpus-size assumptions; its current, fixture-independent counterpart is included.
- `gateway_0_1_skeleton.py` exercises deployment/session/TLS integration assumptions outside the clean-clone kernel/MCP/API/Console artifact boundary.
- `tests/kernel.py` is an import guard/helper, not an executable verification script.

These files are not deleted, rewritten, or represented as failures. They remain inspectable historical or integration evidence and may still be run with their documented prerequisites.

## Semantic scope

This harness changes no kernel behavior, schema, primitive, or EASTER semantic rule. It packages existing current checks behind one deterministic command and supplies isolated fixtures that were previously assumed to exist in a developer database.
