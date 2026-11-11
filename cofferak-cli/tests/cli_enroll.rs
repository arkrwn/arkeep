//! Integration tests for `cofferak-cli`'s `enroll-host` / `enroll-service`
//! support.
//!
//! `cofferak-cli` has no library target (it is a binary crate), so this
//! test file pulls in `src/commands/init.rs` and `src/commands/enroll.rs`
//! directly via `#[path]`, mirroring `cli_init.rs`'s convention. Both
//! modules are declared as siblings at this crate's root so `enroll.rs`'s
//! internal `use super::init::...` resolves the same way it does in the
//! real binary (where both live as siblings under `commands`).

#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/enroll.rs"]
mod enroll;
#[allow(dead_code)]
#[path = "../src/commands/init.rs"]
mod init;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/integrity.rs"]
mod integrity;
#[allow(dead_code)]
#[path = "../src/presence.rs"]
mod presence;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferak_core::acl::Permission;
use cofferak_core::crypto::{decrypt_entry, unwrap_dek_for_host, Aad};
use cofferak_core::format::VaultFile;
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

use enroll::{run_enroll_host_with_seal, run_enroll_service_with_seal};
use init::{run_init_host_with_seal, run_init_root, CliError};

/// A trivial, deterministic, in-memory `HostSeal` fake, identical in shape
/// to `cli_init.rs`'s own `FakeHostSeal`, but parameterized by a tag byte
/// so two distinct fake hosts (A and B) in the same test don't accidentally
/// accept each other's sealed blobs.
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
        "cofferak-cli-enroll-test-{}-{}-{}-{tag}",
        std::process::id(),
        nanos,
        n
    ))
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Build a vault with a single already-enrolled host ("host-a"), returning
/// the data dir and that host's fake seal.
fn setup_single_host(tag: &str) -> (PathBuf, FakeHostSeal) {
    let dir = temp_dir(tag);
    run_init_root(&dir).expect("init --root should succeed");
    let seal_a = FakeHostSeal { tag: 0x5A };
    run_init_host_with_seal(&dir, "host-a", &seal_a).expect("first host enrollment should succeed");
    (dir, seal_a)
}

#[test]
fn run_enroll_host_with_seal_adds_second_host_with_identical_dek() {
    let (dir, seal_a) = setup_single_host("host-pair");
    let seal_b = FakeHostSeal { tag: 0x5B };

    run_enroll_host_with_seal(&dir, "host-a", "host-b", &seal_a, &seal_b)
        .expect("enrolling a second host should succeed");

    let vault =
        VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    assert_eq!(vault.hosts.len(), 2);
    assert!(vault.hosts.contains_key("host-a"));
    assert!(vault.hosts.contains_key("host-b"));

    let sealed_a = std::fs::read(dir.join("hosts/host-a.seal")).expect("host-a seal file");
    let host_key_a = seal_a
        .unseal(&SealedBlob(sealed_a))
        .expect("unsealing host-a's own blob with host-a's own seal must succeed");
    let dek_via_a = unwrap_dek_for_host(&vault.hosts["host-a"], "host-a", &host_key_a)
        .expect("unwrap via host-a should succeed");

    let sealed_b = std::fs::read(dir.join("hosts/host-b.seal")).expect("host-b seal file");
    let host_key_b = seal_b
        .unseal(&SealedBlob(sealed_b))
        .expect("unsealing host-b's own blob with host-b's own seal must succeed");
    let dek_via_b = unwrap_dek_for_host(&vault.hosts["host-b"], "host-b", &host_key_b)
        .expect("unwrap via host-b should succeed");

    assert_eq!(
        dek_via_a, dek_via_b,
        "both hosts must recover the identical DEK"
    );

    cleanup(&dir);
}

#[test]
fn run_enroll_host_with_seal_rejects_already_enrolled_new_host_id() {
    let (dir, seal_a) = setup_single_host("host-dup-new");
    let seal_b = FakeHostSeal { tag: 0x5B };

    run_enroll_host_with_seal(&dir, "host-a", "host-b", &seal_a, &seal_b)
        .expect("enrolling host-b should succeed");

    // Re-enrolling "host-b" (already enrolled) must fail, not silently
    // overwrite its wrap.
    let result = run_enroll_host_with_seal(&dir, "host-a", "host-b", &seal_a, &seal_b);
    assert!(matches!(result, Err(CliError::HostAlreadyEnrolled)));

    let vault =
        VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    assert_eq!(
        vault.hosts.len(),
        2,
        "rejected re-enrollment must not change host count"
    );

    cleanup(&dir);
}

#[test]
fn run_enroll_host_with_seal_unknown_this_host_id_returns_host_not_found() {
    let (dir, _seal_a) = setup_single_host("host-unknown-this");
    let seal_b = FakeHostSeal { tag: 0x5B };
    let bogus_seal = FakeHostSeal { tag: 0x99 };

    let result =
        run_enroll_host_with_seal(&dir, "host-does-not-exist", "host-b", &bogus_seal, &seal_b);
    assert!(matches!(result, Err(CliError::HostNotFound)));

    cleanup(&dir);
}

#[test]
fn run_enroll_service_with_seal_stores_retrievable_token() {
    let (dir, seal_a) = setup_single_host("service-fresh");

    let prefixes = vec!["myapp".to_string(), "other/path".to_string()];
    let permission = Permission::ReadWrite;

    let token = run_enroll_service_with_seal(
        &dir,
        "host-a",
        &seal_a,
        "service-x",
        prefixes.clone(),
        permission,
    )
    .expect("enrolling a service should succeed");

    assert_eq!(token.service_id, "service-x");
    assert_eq!(token.prefixes, prefixes);
    assert_eq!(token.permission, permission);

    let vault =
        VaultFile::load(&dir.join("vault.cofferak")).expect("vault.cofferak should be readable");
    let stored = vault
        .services
        .get("service-x")
        .expect("service entry should be stored");

    let sealed_a = std::fs::read(dir.join("hosts/host-a.seal")).expect("host-a seal file");
    let host_key_a = seal_a
        .unseal(&SealedBlob(sealed_a))
        .expect("unseal should succeed");
    let dek = unwrap_dek_for_host(&vault.hosts["host-a"], "host-a", &host_key_a)
        .expect("unwrap should succeed");

    let plaintext = decrypt_entry(&dek, &Aad::service_token("service-x"), stored)
        .expect("decrypt should succeed");
    let decoded: cofferak_core::acl::AccessToken =
        bincode::deserialize(&plaintext).expect("deserialize should succeed");

    assert_eq!(decoded.service_id, "service-x");
    assert_eq!(decoded.prefixes, prefixes);
    assert_eq!(decoded.permission, permission);
    assert_eq!(decoded.secret, token.secret);

    cleanup(&dir);
}

#[test]
fn run_enroll_service_with_seal_on_missing_vault_returns_vault_missing() {
    let dir = temp_dir("service-missing-vault");
    let seal = FakeHostSeal { tag: 0x5A };

    let result = run_enroll_service_with_seal(
        &dir,
        "host-a",
        &seal,
        "service-x",
        vec!["myapp".to_string()],
        Permission::Read,
    );

    assert!(matches!(result, Err(CliError::VaultMissing)));

    cleanup(&dir);
}
