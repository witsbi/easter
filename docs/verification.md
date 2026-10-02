# Supported verification suite

## Clean-clone command

From the repository root, run:

```bash
PYTHON_BIN=python3.14 ./scripts/run-supported-verification.sh
```

`PYTHON_BIN` may be omitted when `python3` is CPython 3.14.

The command creates a temporary exported copy of the current Git `HEAD`, creates a temporary virtual environment, installs `requirements-mcp.txt`, creates a fresh isolated database for every verification script, and removes the entire temporary workspace on exit. It does not read or modify `data/kernel.db` in the caller's checkout.

Success is exactly:

```text
RESULT: PASS (32/32 scripts)
```

Any dependency, fixture, timeout, or assertion failure exits nonzero and identifies the failing script. The configured count is checked by the harness itself, so adding or removing a supported script requires deliberately updating the expected count.

## Supported environment

The supported artifact-verification environment is:

- CPython 3.14;
- the dependencies installed from `requirements-mcp.txt` (`mcp==2.2.0` at this revision);
- a `sqlite3` command-line client available on `PATH`;
- SQLite with foreign-key, JSON1/`json_valid`, window-function, trigger, and `RETURNING` support;
- loopback socket binding for the HTTP API and Console checks;
- Git and `tar`, used to export the exact committed tree into the isolated workspace.

The remediation was exercised with CPython 3.14.7, Python's SQLite 3.53.4 binding, and SQLite CLI 3.51.0 on macOS. The suite does not require Docker, an EASTER gateway, credentials, an existing ledger, or developer-local record IDs.

## Current suite boundary

The 32-script supported suite covers:

- harness enforcement that assertion-based tests cannot run under optimized Python;
- fresh initialization and refusal to overwrite;
- Authority ordering, scope, and root-model checks using generated isolated prerequisites;
- Receipt minimality and one-operation/one-terminal-Receipt cardinality, including the PR #31 regression;
- State, Evidence, Exception, atomicity, concurrency, branching, and whole-kernel composition checks;
- MCP v0.1/v0.2 boundaries;
- HTTP API mapping, security, pagination, OpenAPI, launch, and argument-shape checks;
- Console inspection, Authority operations, confirmation, CSRF, malformed-input, observability, and human-participant checks;
- focused v0.2 observability behavior.

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
