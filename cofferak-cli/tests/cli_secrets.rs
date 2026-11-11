//! Integration tests for `cofferak-cli`'s `set`/`get`/`rm`/`list` (over a
//! real Unix socket, served by a real `cofferakd::Daemon`) and
//! `rotate-dek` (a local `vault.cofferak` rewrite) support.
//!
//! `cofferak-cli` has no library target, so this file pulls in the CLI
//! source files it needs (`src/client.rs`, `src/commands/*.rs`) via
//! `#[path]`. The daemon-side `protocol`/`audit`/`daemon` modules come
//! from the real `cofferakd` library crate, re-exported at this test's crate
//! root so the CLI files' `crate::protocol` paths resolve to the same
//! types the `Daemon` uses.
//!
//! The socket server itself (bind a `UnixListener`, spawn one thread per
//! connection, decode/dispatch/encode each line through
//! `Daemon::handle_request`) is a deliberately-duplicated, trimmed copy
//! of `cofferakd/src/main.rs`'s own `handle_connection`/accept-loop — that
//! function is private to the `cofferakd` binary, so there is nothing to
//! import; this is the "real `UnixListener` thread serving
//! `Daemon::handle_request`" the task brief calls for, not a mock.

use cofferakd::audit;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/client.rs"]
mod client;
use cofferakd::daemon;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/enroll.rs"]
mod enroll;
#[allow(dead_code)]
#[path = "../src/commands/init.rs"]
mod init;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/integrity.rs"]
mod integrity;
use cofferakd::protocol;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/secrets.rs"]
mod secrets;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::crypto::{
    decrypt_entry, encrypt_entry, generate_root_keypair, unwrap_dek_for_host, Aad,
};
use cofferak_core::format::{VaultEntry, VaultFile};
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

use audit::AuditLog;
use client::Client;
use daemon::{token_key, Daemon};
use enroll::run_enroll_host_with_seal;
use init::{run_init_host_with_seal, run_init_root, vault_path, CliError};
use protocol::{decode_request, encode, Response};
use secrets::{run_get, run_list, run_rm, run_rotate_dek, run_set};

/// A trivial, deterministic, in-memory `HostSeal` fake, parameterized by a
/// tag byte so distinct fake hosts in the same test don't accidentally
/// accept each other's sealed blobs. Identical in shape to
/// `cli_init.rs`/`cli_enroll.rs`'s own `FakeHostSeal`.
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
        "cofferak-cli-secrets-test-{}-{}-{}-{tag}",
        std::process::id(),
        nanos,
        n
    ))
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

fn temp_audit_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cofferak-cli-secrets-audit-{}-{}-{tag}.jsonl",
        std::process::id(),
        nanos
    ))
}

/// Short, `/tmp`-rooted socket path: `AF_UNIX` paths have a small fixed
/// buffer (~104 bytes on macOS/BSD), which `std::env::temp_dir()`'s
/// per-process subdirectories can exceed, so sockets get their own
/// deliberately-short naming scheme instead of reusing `temp_dir`.
fn short_socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    PathBuf::from(format!(
        "/tmp/cofferak-cli-{}-{}-{tag}.sock",
        std::process::id(),
        n
    ))
}

/// Handle to a background thread serving one `Daemon` over a real
/// `UnixListener`; removes the socket file on drop.
struct TestServer {
    socket_path: PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Bind `socket_path` and spawn a background thread that accepts
/// connections and serves `daemon.handle_request` over the real wire
/// protocol — a trimmed copy of `cofferakd/src/main.rs`'s own
/// accept-loop/`handle_connection` (private to that binary, so duplicated
/// here rather than imported). Returns once the socket is bound, so a
/// `Client::connect` issued right after this returns will not race the
/// bind.
fn spawn_daemon_server(daemon: Daemon, socket_path: PathBuf) -> TestServer {
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind test daemon socket");
    let shared = Arc::new(Mutex::new(daemon));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || handle_connection(stream, shared));
        }
    });

    TestServer { socket_path }
}

fn handle_connection(stream: UnixStream, daemon: Arc<Mutex<Daemon>>) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut line = Vec::new();

    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }

        let response = match decode_request(&line) {
            Ok(req) => daemon.lock().unwrap().handle_request(req),
            Err(_) => Response::Err("malformed request".to_string()),
        };

        if writer.write_all(&encode(&response)).is_err() {
            break;
        }
    }

    let _ = writer.shutdown(Shutdown::Both);
}

const TOKEN_SECRET: [u8; 32] = [0x42; 32];

fn myapp_token() -> AccessToken {
    AccessToken {
        service_id: "svc-myapp".to_string(),
        prefixes: vec!["myapp".to_string()],
        permission: Permission::ReadWrite,
        secret: TOKEN_SECRET,
    }
}

/// Build a `Daemon` seeded with one known token/prefix ("svc-myapp",
/// scoped to the "myapp" prefix, read+write), and the path of its audit
/// log (for cleanup).
fn build_test_daemon(tag: &str) -> (Daemon, PathBuf) {
    let (root_pubkey, _root_privkey) = generate_root_keypair().unwrap();
    let vault = VaultFile::new(root_pubkey);
    let mut tokens = BTreeMap::new();
    tokens.insert(token_key(&TOKEN_SECRET), myapp_token());
    let audit_path = temp_audit_path(tag);
    let audit = AuditLog::open(&audit_path).expect("open audit log");
    let dek = [0x7A; 32];
    (Daemon::new(dek, vault, tokens, audit), audit_path)
}

#[test]
fn set_get_list_rm_round_trip_over_real_socket() {
    let (daemon, audit_path) = build_test_daemon("round-trip");
    let socket_path = short_socket_path("round-trip");
    let _server = spawn_daemon_server(daemon, socket_path.clone());

    let client = Client::connect(&socket_path).expect("connect to test daemon");
    let token = token_key(&TOKEN_SECRET);

    run_set(&client, &token, "myapp/KEY", b"hello".to_vec()).expect("set should succeed");

    let value = run_get(&client, &token, "myapp/KEY").expect("get should succeed");
    assert_eq!(value, b"hello".to_vec());

    let listed = run_list(&client, &token, "myapp").expect("list should succeed");
    assert_eq!(listed, vec!["myapp/KEY".to_string()]);

    run_rm(&client, &token, "myapp/KEY").expect("rm should succeed");

    let after_rm = run_get(&client, &token, "myapp/KEY");
    assert!(
        matches!(after_rm, Err(CliError::NotFound)),
        "get after rm should be NotFound, got {after_rm:?}"
    );

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn requests_outside_the_token_prefix_are_denied_not_panicking_or_empty() {
    let (daemon, audit_path) = build_test_daemon("denied");
    let socket_path = short_socket_path("denied");
    let _server = spawn_daemon_server(daemon, socket_path.clone());
    let client = Client::connect(&socket_path).expect("connect to test daemon");
    let token = token_key(&TOKEN_SECRET);

    let get_result = run_get(&client, &token, "other/KEY");
    assert!(
        matches!(get_result, Err(CliError::Denied)),
        "{get_result:?}"
    );

    let set_result = run_set(&client, &token, "other/KEY", b"x".to_vec());
    assert!(
        matches!(set_result, Err(CliError::Denied)),
        "{set_result:?}"
    );

    let rm_result = run_rm(&client, &token, "other/KEY");
    assert!(matches!(rm_result, Err(CliError::Denied)), "{rm_result:?}");

    let list_result = run_list(&client, &token, "other");
    assert!(
        matches!(list_result, Err(CliError::Denied)),
        "{list_result:?}"
    );

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn unknown_token_is_denied_for_every_operation() {
    let (daemon, audit_path) = build_test_daemon("unknown-token");
    let socket_path = short_socket_path("unknown-token");
    let _server = spawn_daemon_server(daemon, socket_path.clone());
    let client = Client::connect(&socket_path).expect("connect to test daemon");
    let bogus_token = "f".repeat(64);

    assert!(matches!(
        run_get(&client, &bogus_token, "myapp/KEY"),
        Err(CliError::Denied)
    ));
    assert!(matches!(
        run_set(&client, &bogus_token, "myapp/KEY", b"x".to_vec()),
        Err(CliError::Denied)
    ));
    assert!(matches!(
        run_rm(&client, &bogus_token, "myapp/KEY"),
        Err(CliError::Denied)
    ));
    assert!(matches!(
        run_list(&client, &bogus_token, "myapp"),
        Err(CliError::Denied)
    ));

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn get_on_a_path_that_was_never_set_returns_not_found() {
    let (daemon, audit_path) = build_test_daemon("not-found");
    let socket_path = short_socket_path("not-found");
    let _server = spawn_daemon_server(daemon, socket_path.clone());
    let client = Client::connect(&socket_path).expect("connect to test daemon");
    let token = token_key(&TOKEN_SECRET);

    let result = run_get(&client, &token, "myapp/NEVER_SET");
    assert!(matches!(result, Err(CliError::NotFound)), "{result:?}");

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn run_rotate_dek_reencrypts_entries_and_services_and_invalidates_old_dek() {
    let dir = temp_dir("rotate");
    run_init_root(&dir).expect("init --root should succeed");

    let seal_a = FakeHostSeal { tag: 0xA1 };
    run_init_host_with_seal(&dir, "host-a", &seal_a).expect("enroll host-a");
    let seal_b = FakeHostSeal { tag: 0xB2 };
    run_enroll_host_with_seal(&dir, "host-a", "host-b", &seal_a, &seal_b).expect("enroll host-b");

    // Recover the DEK that enrollment just generated, to manually seed
    // three entries plus one service token: `init`/`enroll` have no
    // "write a secret" operation of their own, and that's exactly what
    // this task adds.
    let sealed_a = std::fs::read(dir.join("hosts/host-a.seal")).expect("read host-a seal");
    let host_key_a = seal_a.unseal(&SealedBlob(sealed_a)).expect("unseal host-a");

    let mut vault = VaultFile::load(&vault_path(&dir)).expect("load vault");
    let old_wrap_a = vault.hosts["host-a"].clone();
    let old_dek = unwrap_dek_for_host(&old_wrap_a, "host-a", &host_key_a).expect("unwrap old dek");

    let plaintexts: [(&str, Vec<u8>); 3] = [
        ("myapp/ONE", b"secret-one".to_vec()),
        ("myapp/TWO", b"secret-two".to_vec()),
        ("other/THREE", b"secret-three".to_vec()),
    ];
    for (path, value) in &plaintexts {
        vault.entries.insert(
            path.to_string(),
            VaultEntry {
                ciphertext: encrypt_entry(&old_dek, &Aad::entry(path), value),
                version: 1,
                updated_at: 1_700_000_000,
            },
        );
    }
    vault.services.insert(
        "svc-x".to_string(),
        encrypt_entry(
            &old_dek,
            &Aad::service_token("svc-x"),
            b"service-token-bytes",
        ),
    );
    vault.seal(&old_dek); // seed the way the daemon would: a sealed write
    vault.save(&vault_path(&dir)).expect("save seeded vault");

    let hosts: Vec<(String, Box<dyn HostSeal>)> = vec![
        ("host-a".to_string(), Box::new(FakeHostSeal { tag: 0xA1 })),
        ("host-b".to_string(), Box::new(FakeHostSeal { tag: 0xB2 })),
    ];

    run_rotate_dek(&dir, &hosts).expect("rotate-dek should succeed");

    let rotated = VaultFile::load(&vault_path(&dir)).expect("load rotated vault");

    // The new DEK, recovered via either host's (updated) wrap, is the
    // same key, and differs from the old one.
    let new_dek_via_a = unwrap_dek_for_host(&rotated.hosts["host-a"], "host-a", &host_key_a)
        .expect("unwrap new dek via host-a");
    let sealed_b = std::fs::read(dir.join("hosts/host-b.seal")).expect("read host-b seal");
    let host_key_b = seal_b.unseal(&SealedBlob(sealed_b)).expect("unseal host-b");
    let new_dek_via_b = unwrap_dek_for_host(&rotated.hosts["host-b"], "host-b", &host_key_b)
        .expect("unwrap new dek via host-b");
    assert_eq!(
        new_dek_via_a, new_dek_via_b,
        "both hosts must recover the identical new DEK"
    );
    assert_ne!(
        new_dek_via_a, old_dek,
        "rotation must actually change the DEK"
    );

    // Every entry and the service token still decrypt to their original
    // plaintext under the new DEK.
    for (path, value) in &plaintexts {
        let entry = rotated
            .entries
            .get(*path)
            .expect("entry should survive rotation");
        let decrypted = decrypt_entry(&new_dek_via_a, &Aad::entry(path), &entry.ciphertext)
            .expect("entry should decrypt under the new DEK");
        assert_eq!(&decrypted, value);
    }
    let service_ciphertext = rotated
        .services
        .get("svc-x")
        .expect("service token should survive rotation");
    let decrypted_service = decrypt_entry(
        &new_dek_via_a,
        &Aad::service_token("svc-x"),
        service_ciphertext,
    )
    .expect("service token should decrypt under the new DEK");
    assert_eq!(decrypted_service, b"service-token-bytes".to_vec());

    // The OLD DekWrapHost bytes (kept from before rotation) still unwrap
    // to the old DEK via the unchanged host key — rotation never touches
    // the host key itself — but that old DEK can no longer decrypt
    // anything in the now-rotated vault, proving a genuine rotation
    // happened rather than a no-op.
    let old_dek_via_old_wrap = unwrap_dek_for_host(&old_wrap_a, "host-a", &host_key_a)
        .expect("the old wrap bytes still unwrap with the unchanged host key");
    assert_eq!(old_dek_via_old_wrap, old_dek);
    let first_entry = rotated.entries.get(plaintexts[0].0).expect("entry exists");
    let old_dek_decrypt_result = decrypt_entry(
        &old_dek_via_old_wrap,
        &Aad::entry(plaintexts[0].0),
        &first_entry.ciphertext,
    );
    assert!(
        old_dek_decrypt_result.is_err(),
        "the old DEK must fail to decrypt the rotated vault's entries"
    );

    cleanup(&dir);
}

#[test]
fn run_rotate_dek_on_missing_vault_returns_vault_missing() {
    let dir = temp_dir("rotate-missing");
    let hosts: Vec<(String, Box<dyn HostSeal>)> =
        vec![("host-a".to_string(), Box::new(FakeHostSeal { tag: 0xA1 }))];

    let result = run_rotate_dek(&dir, &hosts);
    assert!(matches!(result, Err(CliError::VaultMissing)), "{result:?}");

    cleanup(&dir);
}

#[test]
fn run_rotate_dek_with_an_unenrolled_host_fails_without_panicking_or_rotating() {
    let dir = temp_dir("rotate-unknown-host");
    run_init_root(&dir).expect("init --root should succeed");
    let seal_a = FakeHostSeal { tag: 0xA1 };
    run_init_host_with_seal(&dir, "host-a", &seal_a).expect("enroll host-a");

    let vault_bytes_before =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should exist before the attempt");

    // "host-c" was never enrolled, so it has no sealed blob on disk.
    let hosts: Vec<(String, Box<dyn HostSeal>)> =
        vec![("host-c".to_string(), Box::new(FakeHostSeal { tag: 0xC3 }))];
    let result = run_rotate_dek(&dir, &hosts);
    assert!(
        result.is_err(),
        "rotating against an unenrolled host must fail, not succeed"
    );

    let vault_bytes_after =
        std::fs::read(vault_path(&dir)).expect("vault.cofferak should still exist");
    assert_eq!(
        vault_bytes_before, vault_bytes_after,
        "a failed rotation must not modify vault.cofferak"
    );

    cleanup(&dir);
}
