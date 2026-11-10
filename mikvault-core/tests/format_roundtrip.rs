//! Integration tests for the `mikvault_core::format` on-disk vault format,
//! exercised the same way downstream crates (daemon, CLI) will use it: via
//! the public API only, reading/writing real files on disk.

use mikvault_core::crypto::{
    encrypt_entry, generate_root_keypair, wrap_dek_for_host, wrap_dek_for_root,
};
use mikvault_core::format::{FormatError, VaultEntry, VaultFile, VaultMeta};

fn temp_path(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mikvault-format-roundtrip-{}-{}-{}-{name}",
        std::process::id(),
        nanos,
        n
    ))
}

#[test]
fn vault_file_round_trips_with_no_dek_yet() {
    let (root_pubkey, _root_privkey) = generate_root_keypair();
    let vault = VaultFile::new(root_pubkey);
    assert!(vault.root_wrap.is_none());

    let path = temp_path("fresh.mika");
    vault.save(&path).expect("save should succeed");
    let loaded = VaultFile::load(&path).expect("load should succeed");

    assert_eq!(loaded, vault);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn vault_file_round_trips_with_hosts_services_entries_and_root_wrap() {
    let (root_pubkey, _root_privkey) = generate_root_keypair();
    let dek = [0x5Cu8; 32];

    let mut vault = VaultFile::new(root_pubkey);
    vault.root_wrap = Some(wrap_dek_for_root(&dek, &root_pubkey));
    vault
        .hosts
        .insert("laptop".to_string(), wrap_dek_for_host(&dek, &[0x22u8; 32]));
    vault
        .services
        .insert("github".to_string(), encrypt_entry(&dek, b"gh-token"));
    vault.entries.insert(
        "db/prod".to_string(),
        VaultEntry {
            ciphertext: encrypt_entry(&dek, b"password"),
            version: 3,
            updated_at: 1_730_000_000,
        },
    );

    let path = temp_path("full.mika");
    vault.save(&path).expect("save should succeed");
    let loaded = VaultFile::load(&path).expect("load should succeed");

    assert_eq!(loaded, vault);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn vault_file_load_of_truncated_file_is_corrupt_not_panic() {
    let (root_pubkey, _root_privkey) = generate_root_keypair();
    let dek = [0x9Bu8; 32];
    let mut vault = VaultFile::new(root_pubkey);
    vault.root_wrap = Some(wrap_dek_for_root(&dek, &root_pubkey));
    vault
        .hosts
        .insert("laptop".to_string(), wrap_dek_for_host(&dek, &[0x22u8; 32]));
    vault.entries.insert(
        "secret".to_string(),
        VaultEntry {
            ciphertext: encrypt_entry(&dek, b"super secret value"),
            version: 1,
            updated_at: 1_700_000_000,
        },
    );

    let path = temp_path("truncated.mika");
    vault.save(&path).expect("save should succeed");

    let mut bytes = std::fs::read(&path).expect("read should succeed");
    bytes.truncate(bytes.len().saturating_sub(10));
    std::fs::write(&path, &bytes).expect("write should succeed");

    let result = VaultFile::load(&path);
    assert!(matches!(result, Err(FormatError::Corrupt)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn vault_file_load_of_missing_file_is_io_error_not_panic() {
    let path = temp_path("does-not-exist.mika");
    let result = VaultFile::load(&path);
    assert!(matches!(result, Err(FormatError::Io(_))));
}

#[test]
fn vault_meta_round_trips_and_matches_vault_contents() {
    let (root_pubkey, _root_privkey) = generate_root_keypair();
    let dek = [0x3Du8; 32];
    let mut vault = VaultFile::new(root_pubkey);
    vault.root_wrap = Some(wrap_dek_for_root(&dek, &root_pubkey));
    vault
        .hosts
        .insert("host-1".to_string(), wrap_dek_for_host(&dek, &[0x44u8; 32]));
    vault
        .services
        .insert("slack".to_string(), encrypt_entry(&dek, b"xoxb-token"));

    let meta = VaultMeta::from_vault(&vault);
    let path = temp_path("meta.json");
    meta.save(&path).expect("save should succeed");
    let loaded = VaultMeta::load(&path).expect("load should succeed");

    assert_eq!(loaded, meta);
    assert_eq!(meta.host_ids, vec!["host-1".to_string()]);
    assert_eq!(meta.service_ids, vec!["slack".to_string()]);
    assert_eq!(meta.version, vault.version);
    assert_eq!(meta.root_pubkey_fingerprint.len(), 64); // hex of 32-byte SHA-256

    let _ = std::fs::remove_file(&path);
}

#[test]
fn vault_meta_load_with_missing_field_is_corrupt_not_panic() {
    let path = temp_path("meta-missing-field.json");
    // `service_ids` is missing entirely.
    let malformed = r#"{
        "version": 1,
        "root_pubkey_fingerprint": "deadbeef",
        "host_ids": ["host-1"]
    }"#;
    std::fs::write(&path, malformed).expect("write should succeed");

    let result = VaultMeta::load(&path);
    assert!(matches!(result, Err(FormatError::Corrupt)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn vault_meta_load_of_malformed_json_is_corrupt_not_panic() {
    let path = temp_path("meta-malformed.json");
    std::fs::write(&path, b"not json at all {{{").expect("write should succeed");

    let result = VaultMeta::load(&path);
    assert!(matches!(result, Err(FormatError::Corrupt)));

    let _ = std::fs::remove_file(&path);
}
