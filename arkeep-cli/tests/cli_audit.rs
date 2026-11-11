//! Integration tests for `arkeep-cli`'s `audit tail [--count N]` support
//! (Task 15).
//!
//! `arkeep-cli` has no library target, so this file pulls in
//! `src/commands/audit.rs` and `src/commands/init.rs` (for `CliError`)
//! directly via `#[path]`, mirroring the convention already used by
//! `cli_recover.rs`/`cli_secrets.rs`. Unlike those earlier command
//! modules, `audit.rs` itself depends on `arkeepd::audit::{AuditLog,
//! AuditEntry}` as a real crate dependency (Task 15 gave `arkeepd` a
//! library target precisely so this did not need yet another `#[path]`
//! copy of `arkeepd/src/audit.rs`), so this test builds its fixture log
//! with the same real `arkeepd::audit::{AuditLog, AuditEntry}` types.

#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/audit.rs"]
mod audit;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/init.rs"]
mod init;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use arkeepd::audit::{AuditEntry, AuditLog};

use audit::run_audit_tail;

fn temp_log_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "arkeep-cli-audit-test-{}-{}-{}-{tag}.jsonl",
        std::process::id(),
        nanos,
        n
    ))
}

fn entry(n: i64) -> AuditEntry {
    AuditEntry {
        ts: n,
        service_id: format!("svc-{n}"),
        path: format!("/secrets/{n}"),
        action: "get".to_string(),
        result: "ok".to_string(),
    }
}

#[test]
fn run_audit_tail_returns_last_n_entries_in_order() {
    let path = temp_log_path("tail-last-two");
    let log = AuditLog::open(&path).expect("open audit log");
    log.append(&entry(1)).expect("append entry 1");
    log.append(&entry(2)).expect("append entry 2");
    log.append(&entry(3)).expect("append entry 3");

    let got = run_audit_tail(&path, 2).expect("run_audit_tail should succeed");

    assert_eq!(got, vec![entry(2), entry(3)]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn run_audit_tail_with_n_larger_than_log_returns_everything() {
    let path = temp_log_path("tail-all");
    let log = AuditLog::open(&path).expect("open audit log");
    log.append(&entry(1)).expect("append entry 1");
    log.append(&entry(2)).expect("append entry 2");

    let got = run_audit_tail(&path, 20).expect("run_audit_tail should succeed");

    assert_eq!(got, vec![entry(1), entry(2)]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn run_audit_tail_against_missing_log_returns_empty() {
    let path = temp_log_path("tail-missing");

    let got = run_audit_tail(&path, 10).expect("a missing log should not be an error");

    assert_eq!(got, Vec::new());
}
