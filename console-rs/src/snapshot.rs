//! Consistent, atomic snapshot refresh: copy the live kernel DB into the
//! snapshot the TUI browses, without ever exposing a half-written file.
//!
//! The console's read path always opens the *snapshot* read-only. After
//! a successful write (which goes to the *live* DB through the MCP
//! server), the snapshot is refreshed so the TUI shows the new state.
//!
//! A plain file copy is NOT a consistent SQLite snapshot: under WAL mode
//! committed pages may still live in the `-wal` sidecar, and a concurrent
//! writer can tear the copy mid-transaction, mixing pages from different
//! transaction states. So the refresh goes through SQLite's online backup
//! API, which yields a transactionally consistent image even with
//! concurrent writers. The backup lands in a temp file in the same
//! directory that is renamed over the snapshot, so a concurrent reader
//! never sees a partial DB.
//!
//! The live DB is opened read-only: the console never writes SQLite
//! directly, and even backup-source bookkeeping (e.g. hot-journal
//! recovery) must not touch the live file outside the MCP path.

use anyhow::{Context, Result};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Refresh `snapshot_path` from `live_db` via the SQLite backup API
/// (temp file + rename keeps publication atomic).
pub fn refresh_snapshot(live_db: &str, snapshot_path: &str) -> Result<()> {
    let live = Path::new(live_db);
    let snapshot = Path::new(snapshot_path);
    if !live.exists() {
        anyhow::bail!("live database not found: {live_db}");
    }
    let parent = snapshot.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create snapshot dir: {}", dir.display()))?;
    }
    let tmp = snapshot.with_extension(format!(
        "snapshot-{}.tmp",
        std::process::id()
    ));
    // Read-only source: backup only reads the live DB; a read-write open
    // could roll back a hot journal and modify the live file outside MCP.
    let src = Connection::open_with_flags(live, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("cannot open live DB for backup: {}", live.display()))?;
    let mut dst = Connection::open(&tmp)
        .with_context(|| format!("cannot open snapshot temp DB: {}", tmp.display()))?;
    let backup = Backup::new(&src, &mut dst).context("cannot start SQLite backup")?;
    // Retry across transient writer locks; a kernel-sized DB usually
    // finishes in a single step.
    backup
        .run_to_completion(100, Duration::from_millis(5), None)
        .context("SQLite backup failed")?;
    drop(backup);
    drop(dst);
    drop(src);
    // Best-effort durability of the copy before it becomes visible.
    if let Ok(f) = fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    fs::rename(&tmp, snapshot).with_context(|| {
        format!(
            "cannot publish snapshot {} -> {}",
            tmp.display(),
            snapshot.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_live_db(path: &Path, rows: &[&str]) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE t (v TEXT NOT NULL)").unwrap();
        for r in rows {
            conn.execute("INSERT INTO t (v) VALUES (?1)", [r]).unwrap();
        }
    }

    fn snapshot_rows(path: &Path) -> Vec<String> {
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut stmt = conn.prepare("SELECT v FROM t ORDER BY v").unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap()
    }

    #[test]
    fn refresh_publishes_live_content_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        let snap = dir.path().join("snap.db");
        make_live_db(&live, &["live-v2"]);
        fs::write(&snap, b"stale-v1").unwrap();

        refresh_snapshot(
            live.to_str().unwrap(),
            snap.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(snapshot_rows(&snap), vec!["live-v2".to_string()]);
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x.to_string_lossy().contains("tmp"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    #[test]
    fn refresh_captures_uncheckpointed_wal_content() {
        // Regression test: a file copy of the main DB misses committed
        // pages still sitting in the -wal sidecar; the backup API must not.
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        let snap = dir.path().join("snap.db");
        // Hold the writer open so committed frames stay in the -wal
        // sidecar, never checkpointed into the main DB file.
        let conn = Connection::open(&live).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute_batch("CREATE TABLE t (v TEXT NOT NULL)").unwrap();
        // Committed, but deliberately never checkpointed.
        conn.execute("INSERT INTO t (v) VALUES ('wal-row-1')", [])
            .unwrap();
        conn.execute("INSERT INTO t (v) VALUES ('wal-row-2')", [])
            .unwrap();
        assert!(
            live.with_extension("db-wal").exists(),
            "expected a -wal sidecar for this test"
        );

        refresh_snapshot(
            live.to_str().unwrap(),
            snap.to_str().unwrap(),
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            snapshot_rows(&snap),
            vec!["wal-row-1".to_string(), "wal-row-2".to_string()]
        );
    }

    #[test]
    fn refresh_fails_cleanly_when_live_missing() {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("snap.db");
        fs::write(&snap, b"untouched").unwrap();
        let err = refresh_snapshot(
            dir.path().join("nope.db").to_str().unwrap(),
            snap.to_str().unwrap(),
        )
        .expect_err("must fail");
        assert!(format!("{err:#}").contains("not found"));
        assert_eq!(fs::read(&snap).unwrap(), b"untouched");
    }
}
