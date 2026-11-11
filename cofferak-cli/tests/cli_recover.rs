//! Integration tests for `cofferak-cli`'s `recover --root-key <path>
//! --new-host <id>` support (Task 14: disaster recovery from the offline
//! root private key printed once by `init --root`).
//!
//! `cofferak-cli` has no library target, so this file pulls in
//! `src/commands/init.rs` and `src/commands/recover.rs` directly via
//! `#[path]`, mirroring `cli_enroll.rs`'s / `cli_secrets.rs`'s convention:
//! both modules are declared as siblings at this test binary's crate root
//! so `recover.rs`'s internal `use super::init::...` resolves the same way
//! it does in the real binary.
//!
//! Tests build their own vault directly with `cofferak_core::crypto`
//! (rather than going through `run_init_root`, which only *prints* the
//! root private key to stdout and never returns it) so each test keeps the
//! matching root private key around to write to a temp file and pass to
//! `run_recover`.

#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/init.rs"]
mod init;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/recover.rs"]
mod recover;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferak_core::crypto::{
    generate_root_keypair, unwrap_dek_for_host, wrap_dek_for_host, wrap_dek_for_root,
    RootPrivateKey,
};
use cofferak_core::format::{VaultFile, VaultMeta};
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

use init::{host_seal_path, meta_path, vault_path, CliError};
use recover::run_recover;

/// A trivial, deterministic, in-memory `HostSeal` fake, identical in shape
/// to `cli_init.rs`'s/`cli_enroll.rs`'s own `FakeHostSeal`, parameterized
/// by a tag byte.
struct FakeHostSeal {
    tag: u8,
}

impl HostSeal for FakeHostSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let mut out = Vec::with_capacity(33);
        out.push(self.tag);
        out.extend(key.iter().map(|b| b ^ 0xAA));
        Ok(SealedBlob(out))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if blob.0.len() != 33 || blob.0[0] != self.tag {
            return Err(SealError::Invalid(
                "fake seal: marker/tag mismatch".to_string(),
            ));
        }
        let mut key = [0u8; 32];
        for (i, b) in blob.0[1..].iter().enumerate() {
            key[i] = b ^ 0xAA;
        }
        Ok(key)
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cofferak-cli-recover-test-{}-{}-{}-{tag}",
        std::process::id(),
        nanos,
        n
    ))
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Build a vault shaped like the output of the Task-11/12 flow (`init
/// --root` followed by `init --host`): `root_wrap: Some(_)` and one
/// already-enrolled host ("host-a"). Returns the data dir, the matching
/// root private key, and the DEK (so the test can independently confirm
/// what a correctly-recovered host should unwrap to).
fn setup_vault_with_root_wrap(tag: &str) -> (PathBuf, RootPrivateKey, [u8; 32]) {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).expect("create data dir");

    let (root_pubkey, root_privkey) = generate_root_keypair().unwrap();
    let dek = [0x7Au8; 32];

    let mut vault = VaultFile::new(root_pubkey.clone());
    vault.root_wrap = Some(wrap_dek_for_root(&dek, &root_pubkey).unwrap());

    let host_key_a = [0x11u8; 32];
    vault.hosts.insert(
        "host-a".to_string(),
        wrap_dek_for_host(&dek, "host-a", &host_key_a),
    );

    vault.save(&vault_path(&dir)).expect("save vault");
    let meta = VaultMeta::from_vault(&vault);
    meta.save(&meta_path(&dir)).expect("save meta");

    (dir, root_privkey, dek)
}

fn write_root_key_file(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("root.key");
    std::fs::write(&path, bytes).expect("write root key file");
    path
}

#[test]
fn run_recover_with_matching_root_key_enrolls_new_host_with_recoverable_dek() {
    let (dir, root_privkey, dek) = setup_vault_with_root_wrap("recover-ok");
    let key_path = write_root_key_file(&dir, root_privkey.to_armored().as_bytes());
    let new_seal = FakeHostSeal { tag: 0xC3 };

    run_recover(&dir, &key_path, "host-recovered", &new_seal)
        .expect("recovery with the matching root key should succeed");

    let vault = VaultFile::load(&vault_path(&dir)).expect("vault.cofferak should be readable");
    assert!(vault.hosts.contains_key("host-recovered"));
    assert!(
        vault.hosts.contains_key("host-a"),
        "the previously-enrolled host must survive recovery"
    );

    let sealed = std::fs::read(host_seal_path(&dir, "host-recovered"))
        .expect("the new host's sealed blob should be written to disk");
    let host_key = new_seal
        .unseal(&SealedBlob(sealed))
        .expect("unsealing the new host's own blob with its own seal should succeed");
    let recovered_dek =
        unwrap_dek_for_host(&vault.hosts["host-recovered"], "host-recovered", &host_key)
            .expect("unwrap via the recovered host should succeed");

    assert_eq!(
        recovered_dek, dek,
        "the recovered host must unwrap to the original vault DEK"
    );

    cleanup(&dir);
}

#[test]
fn run_recover_with_wrong_root_key_returns_bad_root_key_and_leaves_vault_unchanged() {
    let (dir, _root_privkey, _dek) = setup_vault_with_root_wrap("recover-bad-key");

    // A well-formed 32-byte key, but not the one that wraps this vault's
    // DEK — exercises "wrong valid keypair", not just "malformed input".
    let (_other_pubkey, wrong_privkey) = generate_root_keypair().unwrap();
    let key_path = write_root_key_file(&dir, wrong_privkey.to_armored().as_bytes());
    let new_seal = FakeHostSeal { tag: 0xC3 };

    let vault_bytes_before =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should exist before the attempt");

    let result = run_recover(&dir, &key_path, "host-recovered", &new_seal);
    assert!(matches!(result, Err(CliError::BadRootKey)), "{result:?}");

    let vault_bytes_after =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should still exist");
    assert_eq!(
        vault_bytes_before, vault_bytes_after,
        "a failed recovery must not modify vault.cofferak"
    );

    assert!(
        !host_seal_path(&dir, "host-recovered").exists(),
        "a failed recovery must not write a sealed blob for the new host either"
    );

    cleanup(&dir);
}

#[test]
fn run_recover_with_random_garbage_key_bytes_returns_bad_root_key_and_leaves_vault_unchanged() {
    let (dir, _root_privkey, _dek) = setup_vault_with_root_wrap("recover-garbage");

    // Random bytes that are not even a 32-byte buffer (nor any particular
    // X25519 scalar) — the "random bytes, not a valid private key" case.
    let garbage_bytes: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let key_path = write_root_key_file(&dir, &garbage_bytes);
    let new_seal = FakeHostSeal { tag: 0xC3 };

    let vault_bytes_before =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should exist before the attempt");

    let result = run_recover(&dir, &key_path, "host-recovered", &new_seal);
    assert!(matches!(result, Err(CliError::BadRootKey)), "{result:?}");

    let vault_bytes_after =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should still exist");
    assert_eq!(
        vault_bytes_before, vault_bytes_after,
        "a failed recovery must not modify vault.cofferak"
    );

    cleanup(&dir);
}

#[test]
fn run_recover_against_missing_vault_returns_vault_missing() {
    let dir = temp_dir("recover-missing-vault");
    std::fs::create_dir_all(&dir).expect("create data dir");
    let key_path = write_root_key_file(&dir, &[0x11u8; 32]);
    let seal = FakeHostSeal { tag: 0xC3 };

    let result = run_recover(&dir, &key_path, "host-recovered", &seal);
    assert!(matches!(result, Err(CliError::VaultMissing)), "{result:?}");

    cleanup(&dir);
}

#[test]
fn run_recover_against_vault_with_no_dek_yet_returns_vault_missing_and_leaves_vault_unchanged() {
    // A vault produced by `init --root` alone (no host enrolled yet) has
    // `root_wrap: None` — there is no DEK to recover, so the brief has
    // this reuse `VaultMissing` rather than a dedicated variant ("a vault
    // with zero hosts has no DEK to recover").
    let dir = temp_dir("recover-no-dek");
    std::fs::create_dir_all(&dir).expect("create data dir");

    let (root_pubkey, root_privkey) = generate_root_keypair().unwrap();
    let vault = VaultFile::new(root_pubkey);
    vault.save(&vault_path(&dir)).expect("save vault");
    let meta = VaultMeta::from_vault(&vault);
    meta.save(&meta_path(&dir)).expect("save meta");

    let key_path = write_root_key_file(&dir, root_privkey.to_armored().as_bytes());
    let seal = FakeHostSeal { tag: 0xC3 };

    let vault_bytes_before =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should exist before the attempt");

    let result = run_recover(&dir, &key_path, "host-recovered", &seal);
    assert!(matches!(result, Err(CliError::VaultMissing)), "{result:?}");

    let vault_bytes_after =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should still exist");
    assert_eq!(
        vault_bytes_before, vault_bytes_after,
        "a failed recovery must not modify vault.cofferak"
    );

    cleanup(&dir);
}
