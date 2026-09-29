//! Atomic snapshot refresh: copy the live kernel DB over the snapshot
//! the TUI browses, without ever exposing a half-written file.
//!
//! The console's read path always opens the *snapshot* read-only. After
//! a successful write (which goes to the *live* DB through the MCP
//! server), the snapshot is refreshed so the TUI shows the new state.
//! The copy goes to a temp file in the same directory and is renamed
//! over the snapshot, so a concurrent reader never sees a partial DB.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Copy `live_db` over `snapshot_path` atomically (temp file + rename).
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
    fs::copy(live, &tmp).with_context(|| {
        format!(
            "cannot copy {} to {}",
            live.display(),
            tmp.display()
        )
    })?;
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

    #[test]
    fn refresh_copies_live_over_snapshot_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        let snap = dir.path().join("snap.db");
        fs::write(&live, b"live-v2").unwrap();
        fs::write(&snap, b"stale-v1").unwrap();

        refresh_snapshot(
            live.to_str().unwrap(),
            snap.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(fs::read(&snap).unwrap(), b"live-v2");
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "tmp").unwrap_or(false))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
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
