//! Durability tests (ADR 0010): a persistent `Daemon` must write every
//! successful `set`/`rm` through to `vault.cofferak` before acknowledging it,
//! must never acknowledge a write it couldn't persist, must refuse to write
//! with a stale DEK after the vault was re-keyed on disk, and must not
//! clobber unrelated changes another writer (the CLI) made to the file.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::crypto::{
    decrypt_entry, encrypt_entry, generate_root_keypair, wrap_dek_for_host, Aad,
};
use cofferak_core::format::VaultFile;
use cofferakd::audit::AuditLog;
use cofferakd::daemon::{token_key, Daemon};
use cofferakd::protocol::{Request, Response};

const SECRET: [u8; 32] = [0x42; 32];
const DEK: [u8; 32] = [0x7A; 32];
const HOST_KEY: [u8; 32] = [0x11; 32];
const HOST_ID: &str = "host-a";

struct Fixture {
    dir: PathBuf,
    vault_path: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(tag: &str) -> Fixture {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cofferakd-persist-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let vault_path = dir.join("vault.cofferak");
    let (root_pubkey, _) = generate_root_keypair().unwrap();
    let mut vault = VaultFile::new(root_pubkey);
    vault.hosts.insert(
        HOST_ID.to_string(),
        wrap_dek_for_host(&DEK, HOST_ID, &HOST_KEY),
    );
    // The service token is enrolled in the vault, exactly as
    // `enroll-service` does, so a reload from disk keeps it.
    vault
        .services
        .insert("svc".to_string(), encrypted_token("svc", "app", SECRET));
    vault.save(&vault_path).unwrap();
    Fixture { dir, vault_path }
}

fn encrypted_token(
    service_id: &str,
    prefix: &str,
    secret: [u8; 32],
) -> cofferak_core::crypto::EncryptedEntry {
    let tok = AccessToken {
        service_id: service_id.to_string(),
        prefixes: vec![prefix.to_string()],
        permission: Permission::ReadWrite,
        secret,
    };
    encrypt_entry(
        &DEK,
        &Aad::service_token(service_id),
        &bincode::serialize(&tok).unwrap(),
    )
}

/// Edit the vault file the way the CLI does: load, change, seal with the
/// DEK (bumping the generation), save.
fn cli_edit(f: &Fixture, change: impl FnOnce(&mut VaultFile)) {
    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    change(&mut disk);
    disk.seal(&DEK);
    disk.save(&f.vault_path).unwrap();
}

fn token() -> String {
    token_key(&SECRET)
}

fn persistent_daemon(f: &Fixture) -> Daemon {
    let vault = VaultFile::load(&f.vault_path).unwrap();
    let host_wrap = vault.hosts[HOST_ID].clone();
    let mut tokens = BTreeMap::new();
    tokens.insert(
        token(),
        AccessToken {
            service_id: "svc".to_string(),
            prefixes: vec!["app".to_string()],
            permission: Permission::ReadWrite,
            secret: SECRET,
        },
    );
    let audit = AuditLog::open(&f.dir.join("audit.jsonl")).unwrap();
    Daemon::new(DEK, vault, tokens, audit).with_persistence(
        f.vault_path.clone(),
        HOST_ID.to_string(),
        host_wrap,
        0,
    )
}

fn set(d: &mut Daemon, path: &str, value: &[u8]) -> Response {
    d.handle_request(Request::Set {
        token: token(),
        path: path.to_string(),
        value: value.to_vec(),
    })
}

fn get(d: &mut Daemon, path: &str) -> Response {
    d.handle_request(Request::Get {
        token: token(),
        path: path.to_string(),
    })
}

#[test]
fn set_is_on_disk_before_it_is_acknowledged_and_survives_a_restart() {
    let f = fixture("set");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/DB_PASSWORD", b"s3cr3t"), Response::Ok);

    // Straight off disk, decrypted with the DEK - not via the daemon.
    let on_disk = VaultFile::load(&f.vault_path).unwrap();
    let entry = &on_disk.entries["app/DB_PASSWORD"];
    assert_eq!(
        decrypt_entry(&DEK, &Aad::entry("app/DB_PASSWORD"), &entry.ciphertext).unwrap(),
        b"s3cr3t"
    );

    // A fresh daemon (simulated restart) sees it.
    drop(d);
    let mut restarted = persistent_daemon(&f);
    assert_eq!(
        get(&mut restarted, "app/DB_PASSWORD"),
        Response::Value(b"s3cr3t".to_vec())
    );
}

#[test]
fn rm_is_removed_from_disk() {
    let f = fixture("rm");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/X", b"1"), Response::Ok);
    let resp = d.handle_request(Request::Rm {
        token: token(),
        path: "app/X".to_string(),
    });
    assert_eq!(resp, Response::Ok);
    assert!(!VaultFile::load(&f.vault_path)
        .unwrap()
        .entries
        .contains_key("app/X"));
}

#[test]
fn write_is_refused_and_not_applied_when_the_vault_was_rekeyed_on_disk() {
    let f = fixture("rekeyed");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/A", b"before"), Response::Ok);

    // Simulate `rotate-dek` running while the daemon is up: this host's
    // wrap on disk changes to wrap a different DEK.
    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    disk.hosts.insert(
        HOST_ID.to_string(),
        wrap_dek_for_host(&[0x99; 32], HOST_ID, &HOST_KEY),
    );
    disk.save(&f.vault_path).unwrap();

    let resp = set(&mut d, "app/A", b"after");
    assert!(matches!(resp, Response::Err(_)), "got {resp:?}");
    // Not applied in memory either: the acknowledged state is still "before".
    assert_eq!(get(&mut d, "app/A"), Response::Value(b"before".to_vec()));
}

#[test]
fn write_is_refused_and_not_applied_when_disk_write_fails() {
    let f = fixture("unwritable");
    let mut d = persistent_daemon(&f);
    // A directory where the vault file should be: unreadable and
    // unwritable as a vault (a plain deletion is restored, see below).
    std::fs::remove_file(&f.vault_path).unwrap();
    std::fs::create_dir(&f.vault_path).unwrap();

    let resp = set(&mut d, "app/B", b"value");
    assert!(matches!(resp, Response::Err(_)), "got {resp:?}");
    assert_eq!(get(&mut d, "app/B"), Response::NotFound);
}

#[test]
fn persisting_does_not_clobber_changes_another_writer_made_to_the_file() {
    let f = fixture("merge");
    let mut d = persistent_daemon(&f);

    // Simulate the CLI enrolling a service (and adding an unrelated entry)
    // after the daemon loaded the vault.
    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    disk.services.insert(
        "new-svc".to_string(),
        encrypted_token("new-svc", "other", [0x55; 32]),
    );
    disk.save(&f.vault_path).unwrap();

    assert_eq!(set(&mut d, "app/C", b"v"), Response::Ok);

    let after = VaultFile::load(&f.vault_path).unwrap();
    assert!(
        after.services.contains_key("new-svc"),
        "service was clobbered"
    );
    assert!(after.entries.contains_key("app/C"));
}

#[test]
fn in_memory_daemon_still_works_without_persistence() {
    let (root_pubkey, _) = generate_root_keypair().unwrap();
    let mut tokens = BTreeMap::new();
    tokens.insert(
        token(),
        AccessToken {
            service_id: "svc".to_string(),
            prefixes: vec!["app".to_string()],
            permission: Permission::ReadWrite,
            secret: SECRET,
        },
    );
    let f = fixture("inmem");
    let audit = AuditLog::open(&f.dir.join("audit.jsonl")).unwrap();
    let mut d = Daemon::new(DEK, VaultFile::new(root_pubkey), tokens, audit);
    assert_eq!(set(&mut d, "app/D", b"x"), Response::Ok);
    assert_eq!(get(&mut d, "app/D"), Response::Value(b"x".to_vec()));
}

#[test]
fn ciphertext_moved_to_another_path_on_disk_is_rejected_not_served() {
    // Crypto format v2 binds each entry to its path (ADR 0011). An attacker
    // who can edit vault.cofferak and copies app/A's ciphertext over app/B
    // must not get app/A's secret back when reading app/B.
    let f = fixture("swap");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/A", b"secret-a"), Response::Ok);
    assert_eq!(set(&mut d, "app/B", b"secret-b"), Response::Ok);
    drop(d);

    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    let a = disk.entries["app/A"].clone();
    disk.entries.insert("app/B".to_string(), a);
    disk.save(&f.vault_path).unwrap();

    let mut restarted = persistent_daemon(&f);
    let resp = get(&mut restarted, "app/B");
    assert_ne!(resp, Response::Value(b"secret-a".to_vec()));
    assert!(matches!(resp, Response::Err(_)), "got {resp:?}");
    assert_eq!(
        get(&mut restarted, "app/A"),
        Response::Value(b"secret-a".to_vec())
    );
}

#[test]
fn changes_written_by_another_process_are_served_without_a_restart() {
    // `cofferak import` / `enroll-service` edit vault.cofferak directly, the
    // daemon notices the file changed and reloads before the next request.
    let f = fixture("reload");
    let mut d = persistent_daemon(&f);
    assert_eq!(get(&mut d, "app/IMPORTED"), Response::NotFound);

    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    disk.entries.insert(
        "app/IMPORTED".to_string(),
        cofferak_core::format::VaultEntry {
            ciphertext: encrypt_entry(&DEK, &Aad::entry("app/IMPORTED"), b"from-import"),
            version: 1,
            updated_at: 0,
        },
    );
    disk.services.insert(
        "late-svc".to_string(),
        encrypted_token("late-svc", "app", [0x66; 32]),
    );
    disk.save(&f.vault_path).unwrap();

    assert_eq!(
        get(&mut d, "app/IMPORTED"),
        Response::Value(b"from-import".to_vec())
    );
    // A service enrolled after the daemon started can authenticate at once.
    let late = d.handle_request(Request::Get {
        token: token_key(&[0x66; 32]),
        path: "app/IMPORTED".to_string(),
    });
    assert_eq!(late, Response::Value(b"from-import".to_vec()));
}

#[test]
fn a_service_removed_from_the_vault_loses_access_immediately() {
    let f = fixture("revoke");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/K", b"v"), Response::Ok);

    cli_edit(&f, |disk| {
        disk.services.remove("svc");
    });

    assert_eq!(get(&mut d, "app/K"), Response::Denied);
}

#[test]
fn own_writes_do_not_trigger_needless_reloads_but_stay_consistent() {
    let f = fixture("ownwrite");
    let mut d = persistent_daemon(&f);
    for i in 0..20 {
        let v = format!("v{i}");
        assert_eq!(set(&mut d, "app/LOOP", v.as_bytes()), Response::Ok);
        assert_eq!(get(&mut d, "app/LOOP"), Response::Value(v.into_bytes()));
    }
}

#[test]
fn daemon_writes_seal_the_vault_and_advance_the_anchor() {
    let f = fixture("seal");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/A", b"1"), Response::Ok);
    assert_eq!(set(&mut d, "app/B", b"2"), Response::Ok);
    let disk = VaultFile::load(&f.vault_path).unwrap();
    assert_eq!(disk.generation, 2);
    assert_eq!(disk.verify(&DEK, Some(2)), Ok(()));
    assert_eq!(
        cofferak_core::format::read_anchor(&f.dir, HOST_ID, &DEK),
        Ok(Some(2))
    );
}

#[test]
fn a_tampered_vault_is_not_loaded_and_blocks_writes() {
    let f = fixture("tamper");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/A", b"original"), Response::Ok);

    // Someone edits the file directly: drops an entry and adds one, without
    // the DEK-derived integrity key.
    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    disk.entries.remove("app/A");
    disk.entries.insert(
        "app/INJECTED".to_string(),
        cofferak_core::format::VaultEntry {
            ciphertext: encrypt_entry(&DEK, &Aad::entry("app/INJECTED"), b"evil"),
            version: 1,
            updated_at: 0,
        },
    );
    disk.save(&f.vault_path).unwrap();

    // Reads keep the last verified state, the injected entry never appears.
    assert_eq!(get(&mut d, "app/A"), Response::Value(b"original".to_vec()));
    assert_eq!(get(&mut d, "app/INJECTED"), Response::NotFound);
    assert!(matches!(set(&mut d, "app/B", b"x"), Response::Err(_)));
}

#[test]
fn an_older_copy_put_back_is_refused() {
    let f = fixture("rollback");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/A", b"v1"), Response::Ok);
    let old = std::fs::read(&f.vault_path).unwrap();
    assert_eq!(set(&mut d, "app/A", b"v2"), Response::Ok);
    assert_eq!(set(&mut d, "app/REVOKE_ME", b"x"), Response::Ok);

    // Replace the file with the authentic but older copy.
    let tmp = f.dir.join("old.tmp");
    std::fs::write(&tmp, &old).unwrap();
    std::fs::rename(&tmp, &f.vault_path).unwrap();

    assert_eq!(get(&mut d, "app/A"), Response::Value(b"v2".to_vec()));
    assert!(matches!(set(&mut d, "app/C", b"x"), Response::Err(_)));

    // A daemon started later still refuses it (the anchor is at 3).
    let anchor = cofferak_core::format::read_anchor(&f.dir, HOST_ID, &DEK).unwrap();
    assert_eq!(anchor, Some(3));
    let on_disk = VaultFile::load(&f.vault_path).unwrap();
    assert!(on_disk.verify(&DEK, anchor).is_err());
}

#[test]
fn a_deleted_vault_is_restored_from_the_daemons_verified_copy() {
    let f = fixture("selfheal");
    let mut d = persistent_daemon(&f);
    assert_eq!(set(&mut d, "app/A", b"kept"), Response::Ok);
    let before = std::fs::read(&f.vault_path).unwrap();

    std::fs::remove_file(&f.vault_path).unwrap();
    // The next request notices and writes the last verified copy back.
    assert_eq!(get(&mut d, "app/A"), Response::Value(b"kept".to_vec()));
    assert_eq!(std::fs::read(&f.vault_path).unwrap(), before);

    // Writes keep working, and a write right after a deletion restores too.
    std::fs::remove_file(&f.vault_path).unwrap();
    assert_eq!(set(&mut d, "app/B", b"new"), Response::Ok);
    let disk = VaultFile::load(&f.vault_path).unwrap();
    assert!(disk.entries.contains_key("app/A") && disk.entries.contains_key("app/B"));
    assert_eq!(disk.verify(&DEK, None), Ok(()));
}
