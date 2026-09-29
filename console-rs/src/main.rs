//! easter-console: a native terminal UI for an EASTER kernel.
//!
//! Browsing is read-only by construction: the snapshot database is opened
//! SQLITE_OPEN_READ_ONLY and the UI reads it directly. Writes (record
//! evidence/decision, propose transition) never touch SQLite here -- each
//! submit spawns one MCP server against the live database, performs a
//! single tools/call, and kills the server before returning. The snapshot
//! is then refreshed from the live DB and the UI reloads.
//!
//! Usage:
//!   easter-console [--db PATH] [--live-db PATH]   browse interactively
//!   easter-console [--db PATH] --dump VIEW         print a view as text and exit
//!       VIEW = lineage | states | transitions | receipts | evidence | grants
//!
//!   --db PATH       snapshot DB to browse (default $EASTER_DB or ./data/kernel.db)
//!   --live-db PATH  live kernel DB for MCP writes (default $EASTER_LIVE_DB;
//!                   when unset, the e/d/t write keys are disabled)

mod db;
mod mcp;
mod model;
mod snapshot;
mod ui;
#[cfg(test)]
mod testutil;

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use ui::{App, AppConfig};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut db_path = env::var("EASTER_DB").unwrap_or_else(|_| "data/kernel.db".to_string());
    let mut live_db = env::var("EASTER_LIVE_DB").ok();
    let mut dump: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db_path = args.get(i).context("--db needs a path")?.clone();
            }
            "--live-db" => {
                i += 1;
                live_db = Some(args.get(i).context("--live-db needs a path")?.clone());
            }
            "--dump" => {
                i += 1;
                dump = Some(args.get(i).context("--dump needs a view name")?.clone());
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other} (try --help)"),
        }
        i += 1;
    }

    let cfg = AppConfig {
        db_path,
        live_db,
        mcp_server_py: env::var("EASTER_MCP_SERVER")
            .unwrap_or_else(|_| default_mcp_server()),
        python: env::var("EASTER_PYTHON").unwrap_or_else(|_| "python3".to_string()),
    };

    if let Some(view) = dump {
        return dump_view(&cfg.db_path, &view);
    }

    run_tui(&cfg)
}

/// Best-effort location of `mcp_server.py`: `EASTER_MCP_SERVER` wins when
/// set; otherwise the first existing candidate wins, searched in order:
/// walking up from the executable (covers `console-rs/target/release`
/// and `target/debug` back to the repo root, plus installed layouts like
/// `<prefix>/bin/easter-console` -> `<prefix>/mcp_server.py`), then the
/// current directory and its parent (covers launching from the repo root
/// or from `console-rs/`, per the README).
/// A missing file is a clear submit-time error, not a startup failure --
/// browsing still works.
fn default_mcp_server() -> String {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    find_mcp_server(exe_dir.as_deref(), &cwd)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mcp_server.py".to_string())
}

/// Ordered candidate search for `mcp_server.py`; the first existing file
/// wins. Pure function of its inputs so the search order is unit-testable.
fn find_mcp_server(exe_dir: Option<&Path>, cwd: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(mut dir) = exe_dir.map(Path::to_path_buf) {
        // console-rs/target/release needs three levels to reach the repo
        // root; keep one spare for deeper install layouts.
        for _ in 0..4 {
            candidates.push(dir.join("mcp_server.py"));
            match dir.parent() {
                Some(parent) => dir = parent.to_path_buf(),
                None => break,
            }
        }
    }
    candidates.push(cwd.join("mcp_server.py"));
    if let Some(parent) = cwd.parent() {
        candidates.push(parent.join("mcp_server.py"));
    }
    candidates.into_iter().find(|c| c.exists())
}

fn print_help() {
    println!("easter-console — browse an EASTER governed-state kernel");
    println!();
    println!("  easter-console [--db PATH] [--live-db PATH]  interactive TUI");
    println!("  easter-console [--db PATH] --dump VIEW       print VIEW as text");
    println!("      VIEW: lineage | states | transitions | receipts | evidence | grants");
    println!();
    println!("  --db PATH       snapshot DB to browse (read-only).");
    println!("                  Defaults to $EASTER_DB or ./data/kernel.db.");
    println!("  --live-db PATH  live kernel DB for MCP writes (e/d/t keys).");
    println!("                  Defaults to $EASTER_LIVE_DB; when unset, writes are disabled.");
    println!("  EASTER_MCP_SERVER / EASTER_PYTHON locate the MCP server subprocess.");
    println!();
    println!("  Writes spawn one MCP server per submit against the live DB,");
    println!("  kill it before returning, then refresh the snapshot from live.");
}

// ---------------------------------------------------------------------------
// Text dump mode (scriptable, and the headless test path)
// ---------------------------------------------------------------------------

fn dump_view(db_path: &str, view: &str) -> Result<()> {
    use crate::model::{
        build_lineage, flatten_tree, grant_status, summarize_evidence, summarize_state,
        summarize_transition,
    };
    use std::collections::HashSet;

    let db = db::Db::open_read_only(db_path)?;
    match view {
        "lineage" => {
            let states = db.states()?;
            let transitions = db.transitions()?;
            let roots = build_lineage(&states, &transitions);
            // Dump fully expanded.
            let all: HashSet<String> = states.iter().map(|s| s.state_id.clone()).collect();
            for row in flatten_tree(&roots, &all) {
                let s = states.iter().find(|s| s.state_id == row.state_id).unwrap();
                let indent = "  ".repeat(row.depth);
                println!("{indent}{}  {}", row.state_id, summarize_state(&s.payload));
            }
        }
        "states" => {
            for s in db.states()? {
                println!(
                    "{}\t{}\t{}",
                    s.state_id,
                    s.created_at,
                    summarize_state(&s.payload)
                );
            }
        }
        "transitions" => {
            for t in db.transitions()? {
                println!(
                    "{}\t{}\t{} -> {}\t{}",
                    t.transition_id,
                    t.created_at,
                    t.from_state_id,
                    t.to_state_id,
                    summarize_transition(&t.payload)
                );
            }
        }
        "receipts" => {
            for r in db.receipts()? {
                println!(
                    "{}\t{}\t{}\t{}",
                    r.receipt_id, r.created_at, r.outcome, r.operation_id
                );
            }
        }
        "evidence" => {
            for e in db.evidence()? {
                println!(
                    "{}\t{}\t{}",
                    e.evidence_id,
                    e.created_at,
                    summarize_evidence(&e.payload)
                );
            }
        }
        "grants" => {
            let revocations = db.revocations()?;
            for g in db.grants()? {
                println!(
                    "{}\t{}\t{} -> {}\t{}",
                    g.grant_id,
                    grant_status(&g, &revocations).label(),
                    g.identity_id,
                    g.authority_id,
                    g.expires_at.as_deref().unwrap_or("never")
                );
            }
        }
        other => anyhow::bail!(
            "unknown view: {other} (lineage|states|transitions|receipts|evidence|grants)"
        ),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive TUI
// ---------------------------------------------------------------------------

fn run_tui(cfg: &AppConfig) -> Result<()> {
    let app = App::load(cfg)?;

    enable_raw_mode().context("cannot enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("cannot enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("cannot create terminal")?;

    let result = event_loop(&mut terminal, app);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut app: App,
) -> Result<()> {
    loop {
        terminal.draw(|f| app.render(f))?;
        if !event::poll(Duration::from_millis(120))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if !app.handle_key(key.code) {
                    return Ok(());
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

#[cfg(test)]
mod default_server_tests {
    use super::*;
    use std::fs;

    /// Fake repo layout: <root>/mcp_server.py plus
    /// <root>/console-rs/target/release/ as the exe dir.
    fn fake_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("mcp_server.py"), b"# fake server").unwrap();
        fs::create_dir_all(dir.path().join("console-rs/target/release")).unwrap();
        fs::create_dir_all(dir.path().join("console-rs")).unwrap();
        dir
    }

    #[test]
    fn finds_server_from_cargo_release_layout() {
        // The documented build: exe at console-rs/target/release, launched
        // from console-rs/ where no mcp_server.py exists. Previously this
        // resolved to the nonexistent console-rs/target/mcp_server.py.
        let repo = fake_repo();
        let exe_dir = repo.path().join("console-rs/target/release");
        let cwd = repo.path().join("console-rs");
        let found = find_mcp_server(Some(exe_dir.as_path()), &cwd)
            .expect("must find the repo-root server");
        assert_eq!(found, repo.path().join("mcp_server.py"));
    }

    #[test]
    fn finds_server_from_cwd_parent() {
        // No usable exe dir (e.g. test harness); launched from console-rs/.
        let repo = fake_repo();
        let cwd = repo.path().join("console-rs");
        let found = find_mcp_server(None, &cwd).expect("must find via cwd parent");
        assert_eq!(found, repo.path().join("mcp_server.py"));
    }

    #[test]
    fn prefers_exe_layout_over_cwd() {
        // An installed layout's server wins over a stray copy in cwd.
        let repo = fake_repo();
        let prefix = repo.path().join("prefix");
        let bin = prefix.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(prefix.join("mcp_server.py"), b"# installed server").unwrap();
        let cwd = repo.path().join("console-rs");
        let found = find_mcp_server(Some(bin.as_path()), &cwd).unwrap();
        assert_eq!(found, prefix.join("mcp_server.py"));
    }

    #[test]
    fn returns_none_when_no_server_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(find_mcp_server(Some(empty.as_path()), &empty).is_none());
    }
}
