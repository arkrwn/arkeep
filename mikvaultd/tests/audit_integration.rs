// The daemon is a binary-only crate, so the audit module is compiled in directly.
#[path = "../src/audit.rs"]
mod audit;

use audit::{AuditEntry, AuditLog};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mikvaultd-audit-it-{}-{}-{}.jsonl",
        tag,
        std::process::id(),
        nanos
    ))
}

fn entry(n: i64) -> AuditEntry {
    AuditEntry {
        ts: n,
        service_id: format!("svc-{n}"),
        path: format!("/secrets/{n}"),
        action: "set".to_string(),
        result: "ok".to_string(),
    }
}

#[test]
fn entries_survive_reopen_and_tail_returns_in_order() {
    let path = temp_path("reopen");
    AuditLog::open(&path).unwrap().append(&entry(1)).unwrap();
    AuditLog::open(&path).unwrap().append(&entry(2)).unwrap();
    AuditLog::open(&path).unwrap().append(&entry(3)).unwrap();

    let log = AuditLog::open(&path).unwrap();
    assert_eq!(log.tail(2).unwrap(), vec![entry(2), entry(3)]);

    let _ = fs::remove_file(&path);
}

#[test]
fn corrupt_line_in_middle_is_skipped() {
    let path = temp_path("corrupt");
    let log = AuditLog::open(&path).unwrap();
    log.append(&entry(1)).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0xff, 0xfe, b'\n'])
        .unwrap();
    log.append(&entry(2)).unwrap();

    assert_eq!(log.tail(5).unwrap(), vec![entry(1), entry(2)]);

    let _ = fs::remove_file(&path);
}
