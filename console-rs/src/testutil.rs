//! Shared test helpers. Test builds only.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("console-rs has no parent dir")
        .to_path_buf()
}

pub fn test_python() -> String {
    std::env::var("EASTER_TEST_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

pub fn mcp_server_py() -> String {
    std::env::var("EASTER_TEST_MCP_SERVER")
        .unwrap_or_else(|_| repo_root().join("mcp_server.py").to_string_lossy().into_owned())
}

/// Fresh kernel DB whose `identity_id` holds the genesis root grant,
/// via the repo's own `initialize.py` (stdlib only).
pub fn fixture_db(dir: &Path, identity_id: &str) -> PathBuf {
    let db = dir.join("fixture.db");
    let status = Command::new(test_python())
        .arg(repo_root().join("initialize.py"))
        .arg(&db)
        .arg(identity_id)
        .status()
        .expect("cannot run initialize.py");
    assert!(status.success(), "initialize.py failed");
    db
}
