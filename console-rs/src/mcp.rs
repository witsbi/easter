//! Minimal MCP client for console write operations.
//!
//! The console reads the kernel database directly (read-only) for
//! browsing, but it must never write SQLite itself: writes go through
//! the kernel, and the only path to the kernel from here is the MCP
//! server subprocess (`mcp_server.py` over stdio), exactly like the
//! Python console.
//!
//! # Enforced short-windowed writes
//!
//! There is deliberately **no persistent-session API** in this module.
//! The single entry point is [`oneshot_call`], which:
//!
//! 1. spawns the MCP server child (the *calling thread* owns the
//!    [`Child`] handle; a worker thread owns only the stdin/stdout
//!    pipes),
//! 2. performs the initialize handshake and exactly one `tools/call`,
//! 3. kills and reaps the child before returning, on every path
//!    (success, tool error, protocol error, timeout).
//!
//! The live kernel database is therefore only ever open for the
//! duration of one confirmed submit -- seconds, not the TUI session
//! lifetime. There is no handle to leak and no code path that keeps
//! the child alive across submits.
//!
//! The timeout is a true kill deadline: the calling thread -- the one
//! that owns the [`Child`] -- performs the kill and the reaping wait
//! itself on expiry, before the error is returned. An earlier design
//! kept the child handle inside the worker thread, which meant a hung
//! server was only reaped whenever the blocked worker happened to
//! notice; that design is gone.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Configuration for one-shot MCP write calls.
#[derive(Clone, Debug)]
pub struct McpConfig {
    /// Python interpreter used to run the MCP server.
    pub python: String,
    /// Path to `mcp_server.py`.
    pub server_py: String,
    /// Kernel database the server opens (`KERNEL_DB_PATH`).
    pub live_db: String,
    /// Hard bound on the whole spawn/handshake/call/teardown exchange.
    pub timeout: Duration,
}

impl McpConfig {
    pub fn new(python: &str, server_py: &str, live_db: &str) -> Self {
        Self {
            python: python.to_string(),
            server_py: server_py.to_string(),
            live_db: live_db.to_string(),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Perform exactly one MCP `tools/call` against a freshly spawned
/// server, then tear the server down. See the module docs for the
/// enforced short-window guarantee.
///
/// Ownership split is the whole trick: the worker thread gets the
/// pipes, the calling thread keeps the [`Child`]. Whichever way the
/// exchange ends, the calling thread -- not the worker -- is the one
/// that kills and reaps.
pub fn oneshot_call(cfg: &McpConfig, tool: &str, args: &Value) -> Result<Value> {
    let mut child = spawn_mcp_server(cfg)?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("mcp server stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("mcp server stdout unavailable"))?;

    let tool = tool.to_string();
    let args = args.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(exchange(stdin, stdout, &tool, &args));
    });

    match rx.recv_timeout(cfg.timeout) {
        Ok(result) => {
            // Worker finished and dropped its pipe ends, so a
            // well-behaved server exits on stdin EOF. Bounded grace
            // for a slow exiter, then SIGKILL -- this path cannot hang.
            reap_child(child, Duration::from_secs(5));
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // THE enforced deadline: the owner of the Child kills and
            // reaps it here, before the error is returned. A hung
            // server cannot survive this call.
            let _ = child.kill();
            let _ = child.wait();
            Err(anyhow!(
                "mcp write timed out after {}s; server child killed and reaped",
                cfg.timeout.as_secs()
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            reap_child(child, Duration::from_secs(5));
            Err(anyhow!("mcp worker thread died before responding"))
        }
    }
}

fn spawn_mcp_server(cfg: &McpConfig) -> Result<Child> {
    if !std::path::Path::new(&cfg.server_py).exists() {
        anyhow::bail!(
            "mcp server not found: {} (set EASTER_MCP_SERVER)",
            cfg.server_py
        );
    }
    Command::new(&cfg.python)
        .arg(&cfg.server_py)
        .env("KERNEL_DB_PATH", &cfg.live_db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot spawn mcp server: {} {}", cfg.python, cfg.server_py))
}

/// Bounded reap: wait up to `grace` for natural exit, then SIGKILL and
/// wait again. Always reaps; never hangs longer than `grace`.
fn reap_child(mut child: Child, grace: Duration) {
    let start = Instant::now();
    while start.elapsed() < grace {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => return,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn exchange(stdin: ChildStdin, stdout: ChildStdout, tool: &str, args: &Value) -> Result<Value> {
    let mut stdin = stdin;
    let mut reader = BufReader::new(stdout);

    let mut next_id: u64 = 1;

    // MCP initialize handshake (protocol version verified against the
    // real server; the server echoes it back on success).
    let init = rpc_request(
        &mut stdin,
        &mut reader,
        next_id,
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "easter-console-rs", "version": "0.2.0"},
        }),
    )?;
    next_id += 1;
    if init.get("protocolVersion").is_none() {
        anyhow::bail!("mcp initialize failed: {}", init);
    }
    let notify = json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string();
    send_line(&mut stdin, &notify)?;

    let result = rpc_request(
        &mut stdin,
        &mut reader,
        next_id,
        "tools/call",
        json!({"name": tool, "arguments": args}),
    )?;
    // Dropping stdin lets a well-behaved server exit on EOF; the
    // caller reaps it regardless via reap_child.
    drop(stdin);

    let is_error = result.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|b| b.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if is_error {
        anyhow::bail!("kernel rejected the call: {text}");
    }
    if text.is_empty() {
        anyhow::bail!("mcp tools/call returned no content: {result}");
    }
    serde_json::from_str(&text).with_context(|| format!("cannot parse tool result: {text}"))
}

fn send_line(stdin: &mut ChildStdin, line: &str) -> Result<()> {
    stdin
        .write_all(line.as_bytes())
        .context("cannot write to mcp server stdin")?;
    stdin
        .write_all(b"\n")
        .context("cannot write to mcp server stdin")?;
    stdin
        .flush()
        .context("cannot flush mcp server stdin")?;
    Ok(())
}

fn rpc_request(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value> {
    let line = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string();
    send_line(stdin, &line)?;
    read_response(reader, id)
}

fn read_response(reader: &mut BufReader<ChildStdout>, expect_id: u64) -> Result<Value> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .context("cannot read mcp server stdout")?;
        if n == 0 {
            anyhow::bail!("mcp server closed stdout unexpectedly");
        }
        let msg: Value =
            serde_json::from_str(line.trim()).context("cannot parse mcp server message")?;
        if let Some(err) = msg.get("error") {
            anyhow::bail!("mcp json-rpc error: {err}");
        }
        match msg.get("id").and_then(Value::as_u64) {
            Some(id) if id == expect_id => {
                return msg
                    .get("result")
                    .cloned()
                    .ok_or_else(|| anyhow!("mcp response has no result: {msg}"));
            }
            // Ignore notifications or responses for other ids.
            _ => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fixture_db, mcp_server_py, test_python};
    use std::process::Command as SysCommand;

    fn cfg_for(db: &str) -> McpConfig {
        McpConfig {
            python: test_python(),
            server_py: mcp_server_py(),
            live_db: db.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn oneshot_record_evidence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture_db(dir.path(), "identity:test-nathan");
        let db = db.to_string_lossy().into_owned();
        let result = oneshot_call(
            &cfg_for(&db),
            "record_evidence",
            &json!({
                "requester_identity_id": "identity:test-nathan",
                "authority_grant_id": "grant:genesis-root",
                "payload": {"note": "rust console write"},
            }),
        )
        .expect("record_evidence failed");
        assert!(result.get("evidence_id").is_some(), "no evidence_id: {result}");
        assert!(result.get("receipt_id").is_some(), "no receipt_id: {result}");

        // The write really landed in the live DB: a second, independent
        // oneshot can read it back, which also proves the first call
        // left no lingering lock or handle behind.
        let back = oneshot_call(
            &cfg_for(&db),
            "get_evidence",
            &json!({"evidence_id": result["evidence_id"].as_str().unwrap()}),
        )
        .expect("get_evidence failed");
        assert_eq!(back["payload"]["note"], "rust console write");
    }

    #[test]
    fn oneshot_surfaces_kernel_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture_db(dir.path(), "identity:test-nathan");
        let db = db.to_string_lossy().into_owned();
        let err = oneshot_call(
            &cfg_for(&db),
            "record_evidence",
            &json!({
                "requester_identity_id": "identity:test-nathan",
                "authority_grant_id": "grant:does-not-exist",
                "payload": {"note": "should be rejected"},
            }),
        )
        .expect_err("nonexistent grant must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("does not exist") || msg.contains("rejected"), "unexpected: {msg}");
    }

    /// Serializes tests that mutate the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `kill -0` succeeds while a pid exists *at all* -- including as a
    /// zombie. So a failing `kill -0` proves the child was both killed
    /// AND reaped (no lingering zombie holding the live DB open).
    fn pid_is_gone(pid: u32) -> bool {
        !SysCommand::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn timeout_kills_and_reaps_child_before_returning() {
        // The "server" writes its own pid to $SLEEPER_PIDFILE, then
        // sleeps without ever speaking MCP. The timeout must not just
        // stop waiting -- it must kill and reap the child before the
        // error is returned. (This is the regression test for the
        // review finding: the old design left the child handle inside
        // the blocked worker thread, so expiry never killed anything.)
        let _env = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sleeper = dir.path().join("sleeper.py");
        std::fs::write(
            &sleeper,
            "import os, time\n\
             pidfile = os.environ.get('SLEEPER_PIDFILE')\n\
             open(pidfile, 'w').write(str(os.getpid()))\n\
             time.sleep(60)\n",
        )
        .unwrap();
        let pidfile = dir.path().join("sleeper.pid");
        std::env::set_var("SLEEPER_PIDFILE", &pidfile);

        let cfg = McpConfig {
            python: test_python(),
            server_py: sleeper.to_string_lossy().into_owned(),
            live_db: String::new(),
            timeout: Duration::from_secs(2),
        };
        let start = Instant::now();
        let err = oneshot_call(&cfg, "record_evidence", &json!({})).expect_err("must time out");
        let elapsed = start.elapsed();
        std::env::remove_var("SLEEPER_PIDFILE");

        assert!(format!("{err:#}").contains("timed out"), "unexpected: {err:#}");
        assert!(elapsed < Duration::from_secs(25), "took too long: {elapsed:?}");

        let pid: u32 = std::fs::read_to_string(&pidfile)
            .expect("sleeper never wrote its pidfile")
            .trim()
            .parse()
            .expect("pidfile was not a pid");
        assert!(
            pid_is_gone(pid),
            "child {pid} still exists after timeout -- the kill deadline did not reap it"
        );
    }

    #[test]
    fn reap_child_kills_stubborn_process() {
        // reap_child must terminate even a process that ignores the
        // grace period, and must not outlive the child as a zombie.
        let child = SysCommand::new("sleep")
            .arg("30")
            .spawn()
            .expect("cannot spawn sleep");
        let pid = child.id();
        reap_child(child, Duration::from_secs(1));
        // try_wait on a moved child is unavailable; kill -0 failing
        // proves the pid is fully gone (killed and reaped).
        assert!(pid_is_gone(pid), "child {pid} survived reap_child");
    }
}
