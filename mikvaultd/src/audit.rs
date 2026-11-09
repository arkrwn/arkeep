//! Append-only audit log, stored as one JSON object per line.

// Consumers (daemon core, CLI) land in later tasks.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// A single audit record. Never holds an access token, only the service id.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub ts: i64,
    pub service_id: String,
    pub path: String,
    pub action: String,
    pub result: String,
}

/// Handle to an append-only JSON-lines audit file.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Opens (creating if needed) the audit file at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        // Create the file up front so a bad path or permission problem surfaces here.
        OpenOptions::new().append(true).create(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Appends one entry as a single JSON line.
    pub fn append(&self, entry: &AuditEntry) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&self.path)?;
        let mut line = Vec::new();
        // If a previous write was cut short, the file ends mid-line. Terminate that
        // fragment first so the new entry starts on its own line instead of being
        // concatenated onto it (which would make the valid entry unparseable).
        if file.metadata()?.len() > 0 {
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                line.push(b'\n');
            }
        }
        line.extend(serde_json::to_vec(entry).map_err(io::Error::other)?);
        line.push(b'\n');
        file.write_all(&line)
    }

    /// Returns the last `n` parseable entries in file order. Invalid lines are skipped.
    pub fn tail(&self, n: usize) -> io::Result<Vec<AuditEntry>> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut entries: Vec<AuditEntry> = bytes
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_slice(line).ok())
            .collect();
        let start = entries.len().saturating_sub(n);
        Ok(entries.split_off(start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mikvaultd-audit-{}-{}-{}.jsonl",
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
            action: "get".to_string(),
            result: "ok".to_string(),
        }
    }

    #[test]
    fn append_then_tail_returns_last_two_in_order() {
        let path = temp_path("tail");
        let log = AuditLog::open(&path).unwrap();
        log.append(&entry(1)).unwrap();
        log.append(&entry(2)).unwrap();
        log.append(&entry(3)).unwrap();

        let got = log.tail(2).unwrap();
        assert_eq!(got, vec![entry(2), entry(3)]);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reopen_keeps_prior_entries() {
        let path = temp_path("reopen");
        {
            let log = AuditLog::open(&path).unwrap();
            log.append(&entry(1)).unwrap();
        }
        {
            let log = AuditLog::open(&path).unwrap();
            log.append(&entry(2)).unwrap();
        }
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(log.tail(2).unwrap(), vec![entry(1), entry(2)]);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_after_partial_line_does_not_concatenate() {
        let path = temp_path("partial");
        let log = AuditLog::open(&path).unwrap();
        log.append(&entry(1)).unwrap();
        // Simulate a crash or short write that left a line with no trailing newline.
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"ts\":2,\"ser")
            .unwrap();
        log.append(&entry(3)).unwrap();

        assert_eq!(log.tail(10).unwrap(), vec![entry(1), entry(3)]);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tail_skips_invalid_json_lines() {
        let path = temp_path("invalid");
        let log = AuditLog::open(&path).unwrap();
        log.append(&entry(1)).unwrap();
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"this is not json\n{\"ts\":9\n").unwrap();
        }
        log.append(&entry(2)).unwrap();

        assert_eq!(log.tail(10).unwrap(), vec![entry(1), entry(2)]);
        assert_eq!(log.tail(1).unwrap(), vec![entry(2)]);

        let _ = fs::remove_file(&path);
    }
}
