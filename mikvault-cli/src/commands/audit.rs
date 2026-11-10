//! `mikvault-cli audit tail [--count N]` (default `N = 20`): print the
//! last `N` entries of the daemon's append-only audit log.
//!
//! Task 15 gave `mikvaultd` a library target (`mikvaultd/src/lib.rs`)
//! specifically so this command could depend on `mikvaultd::audit::{
//! AuditLog, AuditEntry}` directly, rather than pulling
//! `mikvaultd/src/audit.rs`'s source in via `#[path]` the way earlier
//! `mikvault-cli` command modules reuse `mikvaultd`'s binary-only
//! `protocol`/`daemon` modules (see `src/client.rs`'s doc comment) — a
//! `#[path]` workaround from one crate's real `src/` into a sibling
//! crate's `src/` is not viable across crate boundaries the way it is
//! within a single crate's own `tests/`.
//!
//! This is a local, offline read directly against the audit log file on
//! disk (`<data_dir>/audit.jsonl` by default), not a request sent over the
//! daemon's Unix socket — the socket protocol has no audit-tail request,
//! and shouldn't: this is an operator inspecting the daemon's own log
//! file, not a service-token-scoped operation.

use std::path::Path;

use mikvaultd::audit::{AuditEntry, AuditLog};

use super::init::CliError;

/// Return the last `n` parseable entries in the audit log at `log_path`,
/// in file (chronological) order. A missing log file is treated as an
/// empty log (`Ok(Vec::new())`), matching `AuditLog::open`'s own
/// create-if-missing behavior and `AuditLog::tail`'s not-found handling —
/// never an error just because the daemon hasn't written anything yet.
pub fn run_audit_tail(log_path: &Path, n: usize) -> Result<Vec<AuditEntry>, CliError> {
    let log = AuditLog::open(log_path)?;
    let entries = log.tail(n)?;
    Ok(entries)
}

/// Format one audit entry as a single line for `audit tail`'s stdout
/// output: `<ts> <service_id> <action> <path> <result>`.
pub fn format_audit_entry(entry: &AuditEntry) -> String {
    format!(
        "{} {} {} {} {}",
        entry.ts, entry.service_id, entry.action, entry.path, entry.result
    )
}
