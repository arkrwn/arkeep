//! Durability tests (ADR 0010): a persistent `Daemon` must write every
//! successful `set`/`rm` through to `vault.mika` before acknowledging it,
//! must never acknowledge a write it couldn't persist, must refuse to write
//! with a stale DEK after the vault was re-keyed on disk, and must not
//! clobber unrelated changes another writer (the CLI) made to the file.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mikavt_core::acl::{AccessToken, Permission};
use mikavt_core::crypto::{decrypt_entry, encrypt_entry, generate_root_keypair, wrap_dek_for_host};
use mikavt_core::format::VaultFile;
use mikavtd::audit::AuditLog;
use mikavtd::daemon::{token_key, Daemon};
use mikavtd::protocol::{Request, Response};

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
        "mikavtd-persist-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let vault_path = dir.join("vault.mika");
    let (root_pubkey, _) = generate_root_keypair();
    let mut vault = VaultFile::new(root_pubkey);
    vault
        .hosts
        .insert(HOST_ID.to_string(), wrap_dek_for_host(&DEK, &HOST_KEY));
    vault.save(&vault_path).unwrap();
    Fixture { dir, vault_path }
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

    // Straight off disk, decrypted with the DEK — not via the daemon.
    let on_disk = VaultFile::load(&f.vault_path).unwrap();
    let entry = &on_disk.entries["app/DB_PASSWORD"];
    assert_eq!(decrypt_entry(&DEK, &entry.ciphertext).unwrap(), b"s3cr3t");

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
        wrap_dek_for_host(&[0x99; 32], &HOST_KEY),
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
    std::fs::remove_file(&f.vault_path).unwrap();

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
    disk.services
        .insert("new-svc".to_string(), encrypt_entry(&DEK, b"token-blob"));
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
    let (root_pubkey, _) = generate_root_keypair();
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
