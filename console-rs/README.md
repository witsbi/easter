# easter-console

A native terminal console for an [EASTER](https://github.com/witsbi/easter)
governed-state kernel. One static binary for browsing, plus MCP-backed
writes with enforced short write windows.

**Reads are read-only by construction.** Browsing opens a *snapshot* of the
kernel database with `SQLITE_OPEN_READ_ONLY` and never writes. **Writes go
through the kernel only:** each submit (`e` record evidence, `d` record a
human decision, `t` propose a transition) spawns one MCP server against the
*live* database, performs a single `tools/call`, and kills the server before
returning — the live DB is open only for the duration of one confirmed
submit. The snapshot is then refreshed from the live DB and the TUI
reloads. The console never writes SQLite itself and never duplicates kernel
logic.

## Build

```bash
cargo build --release
# binary: ./target/release/easter-console
```

On a Mac this produces a native Apple-silicon (or Intel) binary. The write
path shells out to `python3 mcp_server.py` from the EASTER repo, so the Mac
needs Python with the `mcp` package installed (same requirement as the
Python console).

## Use

```bash
# Interactive TUI: browse a snapshot, writes disabled
easter-console --db ~/snapshots/kernel.db

# Interactive TUI with MCP writes enabled (live DB for the write window)
EASTER_LIVE_DB=~/nginx/easter/data/kernel.db easter-console --db ~/snapshots/kernel.db
# or: easter-console --db ~/snapshots/kernel.db --live-db ~/nginx/easter/data/kernel.db

# Scriptable text views (no terminal needed; always read-only)
easter-console --db kernel.db --dump lineage
easter-console --db kernel.db --dump grants
```

Views for `--dump`: `lineage | states | transitions | receipts | evidence | grants`.

`EASTER_MCP_SERVER` and `EASTER_PYTHON` locate the MCP server subprocess
(defaults: `python3`; server found by walking up from the executable toward
the repo root, then the current directory and its parent). When
`EASTER_LIVE_DB` / `--live-db` is unset, the `e`/`d`/`t`
write keys are disabled and the console is purely a browser.

## The TUI

Six tabs, one per kernel concern:

| Tab | Shows |
|---|---|
| `1` Lineage | The state tree — genesis at the root, branches where agents forked. `Enter` expands/collapses. |
| `2` States | Every committed state with its tip-label summary (`project · status`). |
| `3` Transitions | Handoffs, summarized by their `task`; `Enter` jumps to the resulting state. |
| `4` Receipts | Every operation outcome, color-coded (`ACCEPTED`/`BOOTSTRAP` green, `REJECTED` amber, `FAILED` red); `Enter` jumps to the transition. |
| `5` Evidence | Observations, decisions, anchors; `Enter` jumps to the first citing receipt. |
| `6` Grants | Authority grants with live status — `LIVE`, `EXPIRED`, `REVOKED` (mirrors the kernel's own revocation semantics). |

The right-hand pane shows the selected record in full: pretty-printed
payload, the transition that produced a state, receipts and evidence
attached to a transition, the exception behind a `FAILED` receipt.

### Keys

- `j/k` or `↑/↓` move · `J/K` scroll the detail pane
- `Enter` expand/collapse (Lineage) or jump to the related record
- `1–6` / `Tab` switch tabs · `/` search the current tab · `Esc` clear
- `g`/`G` top/bottom · `r` reload the DB from disk · `?` help · `q` quit
- `e` record evidence · `d` record human decision · `t` propose transition
  (MCP writes; disabled unless `--live-db` / `EASTER_LIVE_DB` is set)

## Notes

- Summaries (`project · status`, handoff `task`, `kind: summary`) follow the
  payload conventions in EASTER's `docs/agent-continuity-payloads.md`.
  They are display conveniences only — the console never treats a
  conventional field as kernel-validated.
- Grant status compares `Z`-suffixed ISO8601 timestamps lexicographically,
  the same representation the kernel writes.
