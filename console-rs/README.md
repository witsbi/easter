# easter-console

A native terminal console for browsing an [EASTER](https://github.com/witsbi/easter)
governed-state kernel. One static binary, no Python, no browser.

**Read-only by construction.** The database is opened `SQLITE_OPEN_READ_ONLY`
and the UI has no write path — it cannot mutate the kernel, only inspect it.

## Build

```bash
cargo build --release
# binary: ./target/release/easter-console
```

On a Mac this produces a native Apple-silicon (or Intel) binary with no
runtime dependencies.

## Use

```bash
# Interactive TUI (DB defaults to $EASTER_DB or ./data/kernel.db)
easter-console --db ~/nginx/easter/data/kernel.db

# Scriptable text views (no terminal needed)
easter-console --db kernel.db --dump lineage
easter-console --db kernel.db --dump grants
```

Views for `--dump`: `lineage | states | transitions | receipts | evidence | grants`.

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

## Notes

- Summaries (`project · status`, handoff `task`, `kind: summary`) follow the
  payload conventions in EASTER's `docs/agent-continuity-payloads.md`.
  They are display conveniences only — the console never treats a
  conventional field as kernel-validated.
- Grant status compares `Z`-suffixed ISO8601 timestamps lexicographically,
  the same representation the kernel writes.
