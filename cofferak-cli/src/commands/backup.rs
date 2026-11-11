//! `cofferak backup` and `cofferak doctor` (ADR 0018).
//!
//! The default backup is a copy of `vault.cofferak` itself. That file is
//! already encrypted, so making the copy needs no key: it runs unattended
//! (a systemd timer, launchd) without root on Linux and without a Touch ID
//! prompt on macOS. A copy can be restored on the same host with
//! `accept-restore`, or on any host with the offline root key (`recover`).
//! `--passphrase-file` or `--to PEER` make a portable bundle instead.

use std::path::{Path, PathBuf};

use cofferak_core::format::{write_atomic, VaultFile};

use super::init::{vault_path, CliError};

/// File name prefix of raw vault backups.
pub const VAULT_PREFIX: &str = "cofferak-vault-";
/// File name prefix of bundle backups (passphrase or peer).
pub const BUNDLE_PREFIX: &str = "cofferak-bundle-";

/// What one backup run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub file: PathBuf,
    pub removed: Vec<PathBuf>,
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time, UTC.
pub fn utc_stamp(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn ensure_dir(dir: &Path) -> Result<(), CliError> {
    let meta = std::fs::symlink_metadata(dir);
    match meta {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(CliError::Invalid(format!(
            "{} exists but is not a directory",
            dir.display()
        ))),
        Err(_) => {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)?;
            Ok(())
        }
    }
}

/// Backups of one kind in `dir`, oldest first. Only regular files whose
/// names match `<prefix><stamp>[-N].<ext>` count, so nothing else in the
/// directory is ever touched.
pub fn list_backups(dir: &Path, prefix: &str, ext: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(prefix)
                && name.ends_with(&format!(".{ext}"))
                && e.file_type().map(|t| t.is_file()).unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// Write `bytes` as a new backup in `dir` (mode 0600, atomic), then delete
/// the oldest backups of the same kind beyond `keep`.
pub fn store_backup(
    dir: &Path,
    prefix: &str,
    ext: &str,
    bytes: &[u8],
    keep: usize,
    now: i64,
) -> Result<BackupReport, CliError> {
    if keep == 0 {
        return Err(CliError::Invalid("--keep must be at least 1".into()));
    }
    ensure_dir(dir)?;
    let stamp = utc_stamp(now);
    let mut file = dir.join(format!("{prefix}{stamp}.{ext}"));
    let mut n = 1;
    while std::fs::symlink_metadata(&file).is_ok() {
        n += 1;
        file = dir.join(format!("{prefix}{stamp}-{n}.{ext}"));
    }
    write_atomic(&file, bytes)?;
    let all = list_backups(dir, prefix, ext);
    let mut removed = Vec::new();
    if all.len() > keep {
        for old in &all[..all.len() - keep] {
            if std::fs::remove_file(old).is_ok() {
                removed.push(old.clone());
            }
        }
    }
    Ok(BackupReport { file, removed })
}

/// Copy `vault.cofferak` into `dir` after checking that it decodes. Needs
/// read access to the vault file only, no key.
pub fn backup_vault_file(
    data_dir: &Path,
    dir: &Path,
    keep: usize,
    now: i64,
) -> Result<BackupReport, CliError> {
    let path = vault_path(data_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Invalid(format!(
                "{} is MISSING: nothing to back up. If the daemon is running it restores the file \
                 itself, otherwise restore the newest backup (see docs/backup.md)",
                path.display()
            )))
        }
        Err(e) => return Err(e.into()),
    };
    VaultFile::from_bytes(&bytes).map_err(|e| {
        CliError::Invalid(format!(
            "{} does not decode ({e}); refusing to back up a damaged file over good backups",
            path.display()
        ))
    })?;
    store_backup(dir, VAULT_PREFIX, "cofferak", &bytes, keep, now)
}

/// Result of one `doctor` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub status: Status,
    pub message: String,
}

fn check(status: Status, message: impl Into<String>) -> Check {
    Check {
        status,
        message: message.into(),
    }
}

/// Health checks that need no key: data directory, vault file, enrolled
/// hosts on this machine, anchors, the daemon socket, and (with
/// `backup_dir`) how old the newest backup is.
pub fn run_doctor(
    data_dir: &Path,
    socket: &Path,
    backup_dir: Option<&Path>,
    max_backup_age_hours: u64,
    now: std::time::SystemTime,
) -> Vec<Check> {
    let mut out = Vec::new();
    match std::fs::symlink_metadata(data_dir) {
        Ok(m) if m.file_type().is_symlink() => out.push(check(
            Status::Warn,
            format!("data directory {} is a symlink", data_dir.display()),
        )),
        Ok(m) if m.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = m.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    out.push(check(
                        Status::Warn,
                        format!(
                            "data directory {} is mode {mode:o}, expected 700",
                            data_dir.display()
                        ),
                    ));
                } else {
                    out.push(check(
                        Status::Ok,
                        format!("data directory {} (mode 700)", data_dir.display()),
                    ));
                }
            }
            #[cfg(not(unix))]
            out.push(check(
                Status::Ok,
                format!("data directory {}", data_dir.display()),
            ));
        }
        _ => {
            out.push(check(
                Status::Fail,
                format!("data directory {} not found", data_dir.display()),
            ));
            return out;
        }
    }

    let vpath = vault_path(data_dir);
    let vault = match std::fs::read(&vpath) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            out.push(check(
                Status::Fail,
                format!(
                    "{} is MISSING. Restore the newest backup (docs/backup.md)",
                    vpath.display()
                ),
            ));
            None
        }
        Err(e) => {
            out.push(check(Status::Fail, format!("{}: {e}", vpath.display())));
            None
        }
        Ok(bytes) => match VaultFile::from_bytes(&bytes) {
            Ok(v) => {
                let sealed = if v.mac.is_empty() {
                    "not sealed yet"
                } else {
                    "integrity code present"
                };
                out.push(check(
                    Status::Ok,
                    format!(
                        "vault: format {}, generation {}, {} secrets, {} services, {} hosts, {sealed}",
                        v.version,
                        v.generation,
                        v.entries.len(),
                        v.services.len(),
                        v.hosts.len()
                    ),
                ));
                Some(v)
            }
            Err(e) => {
                out.push(check(Status::Fail, format!("vault does not decode: {e}")));
                None
            }
        },
    };
    #[cfg(unix)]
    if let Ok(m) = std::fs::metadata(&vpath) {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode() & 0o777;
        if mode != 0o600 {
            out.push(check(
                Status::Warn,
                format!("vault file is mode {mode:o}, expected 600"),
            ));
        }
    }

    if let Some(v) = &vault {
        let local: Vec<&String> = v
            .hosts
            .keys()
            .filter(|h| data_dir.join("hosts").join(format!("{h}.seal")).exists())
            .collect();
        if local.is_empty() {
            out.push(check(
                Status::Warn,
                "no host enrolled from this machine (no hosts/<id>.seal here)",
            ));
        }
        for h in local {
            let anchor = cofferak_core::format::anchor_path(data_dir, h);
            if anchor.exists() || v.generation == 0 {
                out.push(check(
                    Status::Ok,
                    format!("host {h}: sealed key and anchor present"),
                ));
            } else {
                out.push(check(
                    Status::Warn,
                    format!("host {h}: no rollback anchor yet (written on the next change)"),
                ));
            }
        }
    }

    #[cfg(unix)]
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(_) => out.push(check(
            Status::Ok,
            format!("daemon is listening on {}", socket.display()),
        )),
        Err(_) => out.push(check(
            Status::Warn,
            format!("daemon is not reachable on {}", socket.display()),
        )),
    }

    if let Some(dir) = backup_dir {
        let mut all = list_backups(dir, VAULT_PREFIX, "cofferak");
        all.extend(list_backups(dir, BUNDLE_PREFIX, "cfk"));
        let newest = all
            .iter()
            .filter_map(|p| Some((p, std::fs::metadata(p).ok()?.modified().ok()?)))
            .max_by_key(|(_, t)| *t);
        match newest {
            None => out.push(check(
                Status::Warn,
                format!("no backups in {}", dir.display()),
            )),
            Some((p, t)) => {
                let age = now.duration_since(t).unwrap_or_default().as_secs() / 3600;
                let status = if age > max_backup_age_hours {
                    Status::Warn
                } else {
                    Status::Ok
                };
                out.push(check(
                    status,
                    format!(
                        "newest backup {} is {age} hours old ({} backups kept)",
                        p.display(),
                        all.len()
                    ),
                ));
            }
        }
    }
    out
}
