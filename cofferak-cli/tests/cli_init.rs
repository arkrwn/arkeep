//! Integration tests for `cofferak-cli`'s `init --root` / `init --host`
//! support.
//!
//! `cofferak-cli` has no library target (it is a binary crate), so this
//! test file pulls in `src/commands/init.rs` directly via `#[path]` to
//! exercise `run_init_root`, `run_init_host_with_seal`, and `CliError`
//! without going through the real platform `HostSeal` backend (which would
//! otherwise require `systemd-creds` or the macOS Keychain to be available
//! in CI).

#[path = "../src/commands/init.rs"]
mod init;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferak_core::format::VaultFile;
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

use init::{run_init_host_with_seal, run_init_root, CliError};

/// A trivial, deterministic, in-memory `HostSeal` fake: "seals" a key by
/// XOR-ing it with a fixed pattern and prepending a marker byte, so a
/// corrupted/foreign blob is rejected rather than silently accepted. This
/// lets tests exercise the host-enrollment flow without touching
/// `systemd-creds` or the Keychain.
struct FakeHostSeal;

const FAKE_SEAL_MARKER: u8 = 0x5A;
const FAKE_SEAL_PAD: u8 = 0xAA;

impl HostSeal for FakeHostSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let mut out = Vec::with_capacity(33);
        out.push(FAKE_SEAL_MARKER);
        out.extend(key.iter().map(|b| b ^ FAKE_SEAL_PAD));
        Ok(SealedBlob(out))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if blob.0.len() != 33 || blob.0[0] != FAKE_SEAL_MARKER {
            return Err(SealError::Invalid);
        }
        let mut key = [0u8; 32];
        for (i, b) in blob.0[1..].iter().enumerate() {
            key[i] = b ^ FAKE_SEAL_PAD;
        }
        Ok(key)
    }
}

/// Build a unique temp dir for this test, mirroring the convention used by
/// `cofferak-core`'s and `cofferakd`'s own tests.
fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cofferak-cli-init-test-{}-{}-{}-{tag}",
        std::process::id(),
        nanos,
        n
    ))
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn run_init_root_creates_vault_and_meta_with_zero_hosts() {
    let dir = temp_dir("root-fresh");

    let fingerprint = run_init_root(&dir).expect("init --root should succeed on an empty dir");

    let vault = VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    assert!(vault.hosts.is_empty());
    assert!(vault.root_wrap.is_none());

    let meta = cofferak_core::format::VaultMeta::load(&dir.join("meta.json"))
        .expect("meta.json should be readable");
    assert_eq!(meta.host_ids, Vec::<String>::new());
    assert_eq!(fingerprint, meta.root_pubkey_fingerprint);

    cleanup(&dir);
}

#[test]
fn run_init_root_twice_returns_vault_exists_without_overwriting() {
    let dir = temp_dir("root-twice");

    run_init_root(&dir).expect("first init --root should succeed");
    let vault_bytes_before =
        std::fs::read(dir.join("vault.cofferak")).expect("vault.cofferak should exist after first init");

    let result = run_init_root(&dir);
    assert!(matches!(result, Err(CliError::VaultExists)));

    let vault_bytes_after =
        std::fs::read(dir.join("vault.cofferak")).expect("vault.cofferak should still exist");
    assert_eq!(
        vault_bytes_before, vault_bytes_after,
        "a failed second init --root must not overwrite the existing vault"
    );

    cleanup(&dir);
}

#[test]
fn run_init_host_with_seal_on_missing_vault_returns_vault_missing() {
    let dir = temp_dir("host-missing-vault");

    let seal = FakeHostSeal;
    let result = run_init_host_with_seal(&dir, "host-a", &seal);

    assert!(matches!(result, Err(CliError::VaultMissing)));

    cleanup(&dir);
}

#[test]
fn run_init_host_with_seal_enrolls_first_host() {
    let dir = temp_dir("host-first");
    run_init_root(&dir).expect("init --root should succeed");

    let seal = FakeHostSeal;
    run_init_host_with_seal(&dir, "host-a", &seal).expect("first host enrollment should succeed");

    let vault = VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    assert_eq!(vault.hosts.len(), 1);
    assert!(vault.hosts.contains_key("host-a"));
    assert!(
        vault.root_wrap.is_some(),
        "enrolling the first host must set root_wrap"
    );

    let meta = cofferak_core::format::VaultMeta::load(&dir.join("meta.json"))
        .expect("meta.json should be readable");
    assert_eq!(meta.host_ids, vec!["host-a".to_string()]);

    cleanup(&dir);
}

#[test]
fn run_init_host_with_seal_same_host_id_twice_returns_host_already_enrolled() {
    let dir = temp_dir("host-dup");
    run_init_root(&dir).expect("init --root should succeed");

    let seal = FakeHostSeal;
    run_init_host_with_seal(&dir, "host-a", &seal).expect("first host enrollment should succeed");

    let result = run_init_host_with_seal(&dir, "host-a", &seal);
    assert!(matches!(result, Err(CliError::HostAlreadyEnrolled)));

    let vault = VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    assert_eq!(
        vault.hosts.len(),
        1,
        "a rejected duplicate enrollment must not add a second entry"
    );

    cleanup(&dir);
}

#[test]
fn run_init_host_with_seal_second_distinct_host_reuses_existing_dek() {
    let dir = temp_dir("host-second");
    run_init_root(&dir).expect("init --root should succeed");

    let seal = FakeHostSeal;
    run_init_host_with_seal(&dir, "host-a", &seal).expect("first host enrollment should succeed");
    run_init_host_with_seal(&dir, "host-b", &seal)
        .expect("second, distinct host enrollment should succeed");

    let vault = VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    assert_eq!(vault.hosts.len(), 2);
    assert!(vault.hosts.contains_key("host-a"));
    assert!(vault.hosts.contains_key("host-b"));

    cleanup(&dir);
}
