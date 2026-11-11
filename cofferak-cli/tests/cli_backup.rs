//! Integration tests for `cofferak backup` (vault copies, retention) and
//! `cofferak doctor` (ADR 0018).

#[allow(dead_code)]
#[path = "../src/commands/backup.rs"]
mod backup;
#[allow(dead_code)]
#[path = "../src/commands/init.rs"]
mod init;
#[allow(dead_code)]
#[path = "../src/commands/integrity.rs"]
mod integrity;
#[allow(dead_code)]
#[path = "../src/presence.rs"]
mod presence;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use backup::{backup_vault_file, list_backups, run_doctor, utc_stamp, Status, VAULT_PREFIX};
use cofferak_core::format::VaultFile;
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

struct FakeHostSeal;

impl HostSeal for FakeHostSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        Ok(SealedBlob(key.to_vec()))
    }
    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        blob.0
            .as_slice()
            .try_into()
            .map_err(|_| SealError::Invalid("bad".into()))
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "cofferak-backup-test-{tag}-{}-{n}",
        std::process::id()
    ))
}

fn vault(tag: &str) -> PathBuf {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    init::run_init_root(&dir).unwrap();
    init::run_init_host_with_seal(&dir, "h", &FakeHostSeal).unwrap();
    dir
}

#[test]
fn utc_stamps_are_correct_and_sort_by_time() {
    assert_eq!(utc_stamp(0), "19700101T000000Z");
    assert_eq!(utc_stamp(951_782_400), "20000229T000000Z"); // leap day
    assert_eq!(utc_stamp(1_794_396_078), "20261111T112118Z");
    assert!(utc_stamp(1_000) < utc_stamp(100_000));
}

#[test]
fn vault_backups_are_exact_private_copies_and_old_ones_are_pruned() {
    let data = vault("copy");
    let out = temp_dir("copy-out");
    let original = std::fs::read(data.join("vault.cofferak")).unwrap();
    for i in 0..5 {
        let r = backup_vault_file(&data, &out, 3, 1_800_000_000 + i * 86_400).unwrap();
        assert_eq!(std::fs::read(&r.file).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&r.file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
    let kept = list_backups(&out, VAULT_PREFIX, "cofferak");
    assert_eq!(kept.len(), 3);
    assert!(kept[0]
        .to_string_lossy()
        .contains(&utc_stamp(1_800_000_000 + 2 * 86_400)));
    // A file that isn't a backup is never touched.
    std::fs::write(out.join("notes.txt"), "keep me").unwrap();
    backup_vault_file(&data, &out, 1, 1_900_000_000).unwrap();
    assert!(out.join("notes.txt").exists());
    assert_eq!(list_backups(&out, VAULT_PREFIX, "cofferak").len(), 1);
    // Two backups in the same second don't overwrite each other.
    backup_vault_file(&data, &out, 5, 1_900_000_000).unwrap();
    assert_eq!(list_backups(&out, VAULT_PREFIX, "cofferak").len(), 2);
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_missing_or_damaged_vault_is_reported_and_backups_are_kept() {
    let data = vault("missing");
    let out = temp_dir("missing-out");
    backup_vault_file(&data, &out, 2, 1_800_000_000).unwrap();
    std::fs::write(data.join("vault.cofferak"), b"garbage").unwrap();
    let e = backup_vault_file(&data, &out, 2, 1_800_000_100).unwrap_err();
    assert!(e.to_string().contains("does not decode"), "{e}");
    std::fs::remove_file(data.join("vault.cofferak")).unwrap();
    let e = backup_vault_file(&data, &out, 2, 1_800_000_200).unwrap_err();
    assert!(e.to_string().contains("MISSING"), "{e}");
    assert_eq!(list_backups(&out, VAULT_PREFIX, "cofferak").len(), 1);
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_backup_restores_to_a_loadable_vault() {
    let data = vault("restore");
    let out = temp_dir("restore-out");
    let r = backup_vault_file(&data, &out, 2, 1_800_000_000).unwrap();
    std::fs::remove_file(data.join("vault.cofferak")).unwrap();
    std::fs::copy(&r.file, data.join("vault.cofferak")).unwrap();
    let v = VaultFile::load(&data.join("vault.cofferak")).unwrap();
    assert!(v.hosts.contains_key("h"));
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&out);
}

fn worst(checks: &[backup::Check]) -> Status {
    checks.iter().map(|c| c.status).max().unwrap()
}

#[test]
fn doctor_reports_missing_vaults_and_stale_backups() {
    let data = vault("doctor");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let out = temp_dir("doctor-out");
    let socket = data.join("no-daemon.sock");
    let now = std::time::SystemTime::now();

    // Healthy except: no daemon and no backups.
    let checks = run_doctor(&data, &socket, Some(&out), 26, now);
    assert_eq!(worst(&checks), Status::Warn);
    assert!(checks.iter().any(|c| c.message.contains("no backups")));

    backup_vault_file(&data, &out, 2, 1_800_000_000).unwrap();
    let checks = run_doctor(&data, &socket, Some(&out), 26, now);
    assert!(checks
        .iter()
        .any(|c| c.status == Status::Ok && c.message.contains("newest backup")));
    let later = now + std::time::Duration::from_secs(48 * 3600);
    let checks = run_doctor(&data, &socket, Some(&out), 26, later);
    assert!(checks
        .iter()
        .any(|c| c.status == Status::Warn && c.message.contains("newest backup")));

    std::fs::remove_file(data.join("vault.cofferak")).unwrap();
    let checks = run_doctor(&data, &socket, None, 26, now);
    assert_eq!(worst(&checks), Status::Fail);
    assert!(checks.iter().any(|c| c.message.contains("MISSING")));
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&out);
}
