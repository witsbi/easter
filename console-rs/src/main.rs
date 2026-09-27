//! easter-console: a native terminal UI for browsing an EASTER kernel.
//!
//! Read-only by construction: the database is opened SQLITE_OPEN_READ_ONLY
//! and the UI has no write path at all.
//!
//! Usage:
//!   easter-console [--db PATH]            browse interactively
//!   easter-console [--db PATH] --dump VIEW print a view as text and exit
//!       VIEW = lineage | states | transitions | receipts | evidence | grants

mod db;
mod model;
mod ui;

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::env;
use std::io;
use std::time::Duration;
use ui::App;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut db_path = env::var("EASTER_DB").unwrap_or_else(|_| "data/kernel.db".to_string());
    let mut dump: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db_path = args.get(i).context("--db needs a path")?.clone();
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

    if let Some(view) = dump {
        return dump_view(&db_path, &view);
    }

    run_tui(&db_path)
}

fn print_help() {
    println!("easter-console — browse an EASTER governed-state kernel (read-only)");
    println!();
    println!("  easter-console [--db PATH]             interactive TUI");
    println!("  easter-console [--db PATH] --dump VIEW  print VIEW as text");
    println!("      VIEW: lineage | states | transitions | receipts | evidence | grants");
    println!();
    println!("  The DB path defaults to $EASTER_DB or ./data/kernel.db.");
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

fn run_tui(db_path: &str) -> Result<()> {
    let app = App::load(db_path)?;

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
