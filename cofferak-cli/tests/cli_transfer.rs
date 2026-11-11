//! Tests for `commands/transfer.rs` (ADR 0012): encrypted export/import
//! bundles between two vaults, and `.env` import/export over a real
//! daemon socket.

#[allow(dead_code)]
#[path = "../src/client.rs"]
mod client;
#[allow(dead_code)]
#[path = "../src/commands/enroll.rs"]
mod enroll;
#[allow(dead_code)]
#[path = "../src/commands/init.rs"]
mod init;
#[allow(dead_code)]
#[path = "../src/commands/integrity.rs"]
mod integrity;
#[allow(dead_code)]
#[path = "../src/commands/secrets.rs"]
mod secrets;
#[allow(dead_code)]
#[path = "../src/commands/transfer.rs"]
mod transfer;
use cofferakd::{audit, daemon, protocol};

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
use enroll::run_enroll_service_with_seal;
use init::{host_seal_path, run_init_host_with_seal, run_init_root, vault_path, CliError};
use protocol::{decode_request, encode, Response};

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
        "cofferak-cli-transfer-test-{}-{}-{}-{tag}",
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
        "cofferak-cli-transfer-audit-{}-{}-{tag}.jsonl",
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
        "/tmp/cfk-xfer-{}-{}-{tag}.sock",
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

const PASS: &[u8] = b"correct horse battery staple";
const FAST: u32 = 100_000;

/// A vault with one host (fake seal `tag`), one enrolled service, and the
/// given secrets written directly. Returns (dir, service token).
fn vault_with(tag: &str, seal_tag: u8, secrets: &[(&str, &[u8])]) -> (PathBuf, AccessToken) {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    run_init_root(&dir).unwrap();
    let seal = FakeHostSeal { tag: seal_tag };
    run_init_host_with_seal(&dir, "h", &seal).unwrap();
    let token = run_enroll_service_with_seal(
        &dir,
        "h",
        &seal,
        "app",
        vec!["app".into()],
        Permission::ReadWrite,
    )
    .unwrap();
    let mut vault = VaultFile::load(&vault_path(&dir)).unwrap();
    let dek = dek_of(&dir, &vault, seal_tag);
    for (p, v) in secrets {
        vault.entries.insert(
            p.to_string(),
            VaultEntry {
                ciphertext: encrypt_entry(&dek, &Aad::entry(p), v),
                version: 2,
                updated_at: 1_700_000_000,
            },
        );
    }
    vault.seal(&dek); // a sealed write, as the daemon makes
    vault.save(&vault_path(&dir)).unwrap();
    (dir, token)
}

fn dek_of(dir: &Path, vault: &VaultFile, seal_tag: u8) -> [u8; 32] {
    let sealed = std::fs::read(host_seal_path(dir, "h")).unwrap();
    let key = FakeHostSeal { tag: seal_tag }
        .unseal(&SealedBlob(sealed))
        .unwrap();
    unwrap_dek_for_host(&vault.hosts["h"], "h", &key).unwrap()
}

fn value_of(dir: &Path, seal_tag: u8, path: &str) -> Option<Vec<u8>> {
    let vault = VaultFile::load(&vault_path(dir)).unwrap();
    let dek = dek_of(dir, &vault, seal_tag);
    vault
        .entries
        .get(path)
        .map(|e| decrypt_entry(&dek, &Aad::entry(path), &e.ciphertext).unwrap())
}

#[test]
fn bundle_moves_every_secret_and_token_to_another_vault() {
    let key: Vec<u8> = (0..=255u8).collect();
    let (src, token) = vault_with("src", 1, &[("app/DB", b"p@ss"), ("app/ssh/key", &key)]);
    let (dst, _) = vault_with("dst", 2, &[("app/LOCAL", b"keep")]);

    let (bytes, rep) = transfer::run_export_with_seal(
        &src,
        "h",
        &FakeHostSeal { tag: 1 },
        PASS,
        FAST,
        &transfer::Selection::everything(),
    )
    .unwrap();
    assert_eq!((rep.entries, rep.services), (2, 1));

    let r = transfer::run_import_with_seal(
        &dst,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Passphrase(PASS),
        false,
        true,
        false,
    )
    .unwrap();
    assert_eq!(r.entries_added, 2);
    // The destination already had a service called "app" (with a different
    // token): kept, because --overwrite wasn't given.
    assert_eq!(r.services_skipped, vec!["app".to_string()]);
    assert_eq!(value_of(&dst, 2, "app/DB").unwrap(), b"p@ss");
    assert_eq!(value_of(&dst, 2, "app/ssh/key").unwrap(), key);
    assert_eq!(value_of(&dst, 2, "app/LOCAL").unwrap(), b"keep");

    // With --overwrite the source's token replaces it, so the app keeps
    // working with the token it already has.
    let r = transfer::run_import_with_seal(
        &dst,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Passphrase(PASS),
        true,
        true,
        false,
    )
    .unwrap();
    assert_eq!((r.entries_replaced, r.services_replaced), (2, 1));
    let vault = VaultFile::load(&vault_path(&dst)).unwrap();
    let dek = dek_of(&dst, &vault, 2);
    let plain = decrypt_entry(&dek, &Aad::service_token("app"), &vault.services["app"]).unwrap();
    let t: AccessToken = bincode::deserialize(&plain).unwrap();
    assert_eq!(t.secret, token.secret);
    cleanup(&src);
    cleanup(&dst);
}

#[test]
fn import_dry_run_and_wrong_passphrase_change_nothing() {
    let (src, _) = vault_with("src2", 1, &[("app/A", b"1")]);
    let (dst, _) = vault_with("dst2", 2, &[]);
    let (bytes, _) = transfer::run_export_with_seal(
        &src,
        "h",
        &FakeHostSeal { tag: 1 },
        PASS,
        FAST,
        &transfer::Selection::everything(),
    )
    .unwrap();
    let before = std::fs::read(vault_path(&dst)).unwrap();

    let r = transfer::run_import_with_seal(
        &dst,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Passphrase(PASS),
        false,
        true,
        true,
    )
    .unwrap();
    assert_eq!(r.entries_added, 1);
    assert_eq!(
        std::fs::read(vault_path(&dst)).unwrap(),
        before,
        "dry run wrote"
    );

    let e = transfer::run_import_with_seal(
        &dst,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Passphrase(b"not the passphrase!"),
        false,
        true,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(e, CliError::Invalid(ref m) if m.contains("wrong passphrase")),
        "{e}"
    );
    assert_eq!(std::fs::read(vault_path(&dst)).unwrap(), before);
    cleanup(&src);
    cleanup(&dst);
}

#[test]
fn export_refuses_weak_passphrase_and_missing_vault() {
    let (src, _) = vault_with("src3", 1, &[]);
    let e = transfer::run_export_with_seal(
        &src,
        "h",
        &FakeHostSeal { tag: 1 },
        b"short",
        FAST,
        &transfer::Selection::everything(),
    )
    .unwrap_err();
    assert!(matches!(e, CliError::Invalid(_)));
    let e = transfer::run_export_with_seal(
        &temp_dir("none"),
        "h",
        &FakeHostSeal { tag: 1 },
        PASS,
        FAST,
        &transfer::Selection::everything(),
    )
    .unwrap_err();
    assert!(matches!(e, CliError::VaultMissing));
    cleanup(&src);
}

const TOKEN_SECRET: [u8; 32] = [0x42; 32];

fn env_daemon(tag: &str) -> (TestServer, Client, String) {
    let (root_pubkey, _) = generate_root_keypair().unwrap();
    let mut tokens = BTreeMap::new();
    tokens.insert(
        token_key(&TOKEN_SECRET),
        AccessToken {
            service_id: "app".into(),
            prefixes: vec!["app".into()],
            permission: Permission::ReadWrite,
            secret: TOKEN_SECRET,
        },
    );
    let audit = AuditLog::open(&temp_audit_path(tag)).unwrap();
    let daemon = Daemon::new([0x7A; 32], VaultFile::new(root_pubkey), tokens, audit);
    let sock = short_socket_path(tag);
    let server = spawn_daemon_server(daemon, sock.clone());
    (
        server,
        Client::connect(&sock).unwrap(),
        token_key(&TOKEN_SECRET),
    )
}

const TRICKY_ENV: &str = r#"# comment
export DB_HOST=db.internal
DB_PASSWORD="p@ss \"q\" $X"
API_KEY=abc=123  # inline
PEM="-----BEGIN-----
MIIabc
-----END-----"
EMPTY=
"#;

#[test]
fn import_env_stores_each_variable_and_respects_existing_values() {
    let (_s, client, tok) = env_daemon("ienv");
    let dry = transfer::run_import_env(&client, &tok, "app/env/", TRICKY_ENV, false, true).unwrap();
    assert_eq!(dry.added.len(), 5);
    assert!(
        secrets::run_list(&client, &tok, "app/env")
            .unwrap()
            .is_empty(),
        "dry run wrote"
    );

    let r = transfer::run_import_env(&client, &tok, "app/env", TRICKY_ENV, false, false).unwrap();
    assert_eq!(
        r.added,
        vec!["DB_HOST", "DB_PASSWORD", "API_KEY", "PEM", "EMPTY"]
    );
    assert_eq!(
        secrets::run_get(&client, &tok, "app/env/DB_PASSWORD").unwrap(),
        b"p@ss \"q\" $X"
    );
    assert_eq!(
        secrets::run_get(&client, &tok, "app/env/API_KEY").unwrap(),
        b"abc=123"
    );
    assert_eq!(
        secrets::run_get(&client, &tok, "app/env/PEM").unwrap(),
        b"-----BEGIN-----\nMIIabc\n-----END-----"
    );

    secrets::run_set(&client, &tok, "app/env/API_KEY", b"changed".to_vec()).unwrap();
    let r = transfer::run_import_env(&client, &tok, "app/env", TRICKY_ENV, false, false).unwrap();
    assert_eq!(r.skipped.len(), 5);
    assert_eq!(
        secrets::run_get(&client, &tok, "app/env/API_KEY").unwrap(),
        b"changed"
    );
    let r = transfer::run_import_env(&client, &tok, "app/env", TRICKY_ENV, true, false).unwrap();
    assert_eq!(r.replaced.len(), 5);
    assert_eq!(
        secrets::run_get(&client, &tok, "app/env/API_KEY").unwrap(),
        b"abc=123"
    );
}

#[test]
fn import_env_reports_syntax_errors_and_respects_the_token_prefix() {
    let (_s, client, tok) = env_daemon("ienv2");
    let e = transfer::run_import_env(&client, &tok, "app/env", "A=1\n2BAD=x\n", false, false)
        .unwrap_err();
    assert!(
        matches!(e, CliError::Invalid(ref m) if m.contains("line 2")),
        "{e}"
    );
    let e =
        transfer::run_import_env(&client, &tok, "other/env", "A=1\n", false, false).unwrap_err();
    assert!(matches!(e, CliError::Denied), "{e}");
}

#[test]
fn export_env_round_trips_and_skips_what_cannot_be_an_env_var() {
    let (_s, client, tok) = env_daemon("eenv");
    transfer::run_import_env(&client, &tok, "app/env", TRICKY_ENV, false, false).unwrap();
    secrets::run_set(&client, &tok, "app/env/nested/X", b"n".to_vec()).unwrap();
    secrets::run_set(&client, &tok, "app/env/bad-name", b"b".to_vec()).unwrap();
    secrets::run_set(&client, &tok, "app/env/BIN", vec![0xff, 0xfe, 0x00]).unwrap();

    let (text, skipped) = transfer::run_export_env(&client, &tok, "app/env").unwrap();
    assert_eq!(skipped.len(), 3, "{skipped:?}");
    let parsed = cofferak_core::dotenv::parse(&text).unwrap();
    let got: BTreeMap<String, String> = parsed.into_iter().map(|v| (v.key, v.value)).collect();
    let want: BTreeMap<String, String> = cofferak_core::dotenv::parse(TRICKY_ENV)
        .unwrap()
        .into_iter()
        .map(|v| (v.key, v.value))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn collect_env_merges_prefixes_in_order() {
    let (_s, client, tok) = env_daemon("cenv");
    secrets::run_set(&client, &tok, "app/base/A", b"base".to_vec()).unwrap();
    secrets::run_set(&client, &tok, "app/base/B", b"base".to_vec()).unwrap();
    secrets::run_set(&client, &tok, "app/prod/A", b"prod".to_vec()).unwrap();
    let (vars, _) =
        transfer::collect_env(&client, &tok, &["app/base".into(), "app/prod".into()]).unwrap();
    assert_eq!(&*vars["A"], b"prod");
    assert_eq!(&*vars["B"], b"base");
}

// ---- peer transfers (ADR 0013) ----

fn pair(a: &Path, a_tag: u8, a_name: &str, b: &Path, b_tag: u8, b_name: &str) {
    let a_id = transfer::run_identity_with_seal(a, "h", &FakeHostSeal { tag: a_tag }).unwrap();
    let b_id = transfer::run_identity_with_seal(b, "h", &FakeHostSeal { tag: b_tag }).unwrap();
    transfer::run_peer_add_with_seal(a, "h", &FakeHostSeal { tag: a_tag }, b_name, &b_id, false)
        .unwrap();
    transfer::run_peer_add_with_seal(b, "h", &FakeHostSeal { tag: b_tag }, a_name, &a_id, false)
        .unwrap();
}

#[test]
fn peer_transfer_moves_secrets_both_ways_and_reencrypts_under_the_receivers_key() {
    let (mac, _) = vault_with(
        "pmac",
        1,
        &[("app/MAC_ONLY", b"from-mac"), ("other/X", b"x")],
    );
    let (srv, _) = vault_with("psrv", 2, &[("app/SRV_ONLY", b"from-server")]);
    pair(&mac, 1, "mac", &srv, 2, "server");

    // Mac -> server, only app/*.
    let sel = transfer::Selection {
        prefixes: vec!["app".into()],
        include_tokens: false,
    };
    let (bytes, rep) =
        transfer::run_export_to_peer_with_seal(&mac, "h", &FakeHostSeal { tag: 1 }, "server", &sel)
            .unwrap();
    assert_eq!((rep.entries, rep.services), (1, 0));
    let r = transfer::run_import_with_seal(
        &srv,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Identity { from: None },
        false,
        true,
        false,
    )
    .unwrap();
    assert_eq!(r.from_peer.as_deref(), Some("mac"));
    assert_eq!(r.entries_added, 1);
    // Readable on the server with the server's own key only.
    assert_eq!(value_of(&srv, 2, "app/MAC_ONLY").unwrap(), b"from-mac");
    assert!(
        value_of(&srv, 2, "other/X").is_none(),
        "prefix filter leaked"
    );

    // Server -> mac (append).
    let (back, _) = transfer::run_export_to_peer_with_seal(
        &srv,
        "h",
        &FakeHostSeal { tag: 2 },
        "mac",
        &transfer::Selection::everything(),
    )
    .unwrap();
    let r = transfer::run_import_with_seal(
        &mac,
        "h",
        &FakeHostSeal { tag: 1 },
        &back,
        transfer::ImportKey::Identity { from: None },
        false,
        true,
        false,
    )
    .unwrap();
    assert_eq!(r.from_peer.as_deref(), Some("server"));
    assert_eq!(value_of(&mac, 1, "app/SRV_ONLY").unwrap(), b"from-server");
    cleanup(&mac);
    cleanup(&srv);
}

#[test]
fn transfers_from_untrusted_coffers_or_for_other_coffers_are_refused() {
    let (mac, _) = vault_with("umac", 1, &[("app/A", b"a")]);
    let (srv, _) = vault_with("usrv", 2, &[]);
    let (evil, _) = vault_with("uevil", 3, &[("app/A", b"evil")]);
    pair(&mac, 1, "mac", &srv, 2, "server");
    // `evil` knows the server's public identity and trusts it, but the
    // server doesn't trust `evil`.
    let srv_id = transfer::run_identity_with_seal(&srv, "h", &FakeHostSeal { tag: 2 }).unwrap();
    transfer::run_peer_add_with_seal(
        &evil,
        "h",
        &FakeHostSeal { tag: 3 },
        "server",
        &srv_id,
        false,
    )
    .unwrap();
    let (forged, _) = transfer::run_export_to_peer_with_seal(
        &evil,
        "h",
        &FakeHostSeal { tag: 3 },
        "server",
        &transfer::Selection::everything(),
    )
    .unwrap();
    let before = std::fs::read(vault_path(&srv)).unwrap();
    let e = transfer::run_import_with_seal(
        &srv,
        "h",
        &FakeHostSeal { tag: 2 },
        &forged,
        transfer::ImportKey::Identity { from: None },
        false,
        true,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(e, CliError::Invalid(ref m) if m.contains("untrusted")),
        "{e}"
    );
    assert_eq!(std::fs::read(vault_path(&srv)).unwrap(), before);

    // A transfer the mac made for the server can't be imported by `evil`.
    let (for_srv, _) = transfer::run_export_to_peer_with_seal(
        &mac,
        "h",
        &FakeHostSeal { tag: 1 },
        "server",
        &transfer::Selection::everything(),
    )
    .unwrap();
    let e = transfer::run_import_with_seal(
        &evil,
        "h",
        &FakeHostSeal { tag: 3 },
        &for_srv,
        transfer::ImportKey::Identity { from: None },
        false,
        true,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(e, CliError::Invalid(ref m) if m.contains("different coffer")),
        "{e}"
    );

    // Exporting to an unknown peer fails clearly.
    let e = transfer::run_export_to_peer_with_seal(
        &mac,
        "h",
        &FakeHostSeal { tag: 1 },
        "nobody",
        &transfer::Selection::everything(),
    )
    .unwrap_err();
    assert!(
        matches!(e, CliError::Invalid(ref m) if m.contains("no trusted peer")),
        "{e}"
    );
    for d in [&mac, &srv, &evil] {
        cleanup(d);
    }
}

#[test]
fn identity_and_peers_survive_dek_rotation() {
    let (mac, _) = vault_with("rmac", 1, &[("app/A", b"a")]);
    let (srv, _) = vault_with("rsrv", 2, &[]);
    pair(&mac, 1, "mac", &srv, 2, "server");
    let before = transfer::run_identity_with_seal(&srv, "h", &FakeHostSeal { tag: 2 }).unwrap();
    let hosts: Vec<(String, Box<dyn HostSeal>)> =
        vec![("h".into(), Box::new(FakeHostSeal { tag: 2 }))];
    secrets::run_rotate_dek(&srv, &hosts).unwrap();
    let after = transfer::run_identity_with_seal(&srv, "h", &FakeHostSeal { tag: 2 }).unwrap();
    assert_eq!(before, after, "identity changed across rotate-dek");
    let peers = transfer::run_peer_list_with_seal(&srv, "h", &FakeHostSeal { tag: 2 }).unwrap();
    assert!(peers.contains_key("mac"));
    let (bytes, _) = transfer::run_export_to_peer_with_seal(
        &mac,
        "h",
        &FakeHostSeal { tag: 1 },
        "server",
        &transfer::Selection::everything(),
    )
    .unwrap();
    transfer::run_import_with_seal(
        &srv,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Identity { from: None },
        false,
        true,
        false,
    )
    .unwrap();
    assert_eq!(value_of(&srv, 2, "app/A").unwrap(), b"a");
    cleanup(&mac);
    cleanup(&srv);
}

#[test]
fn peer_names_are_validated_and_self_or_duplicate_trust_refused() {
    let (a, _) = vault_with("na", 1, &[]);
    let (b, _) = vault_with("nb", 2, &[]);
    let a_id = transfer::run_identity_with_seal(&a, "h", &FakeHostSeal { tag: 1 }).unwrap();
    let b_id = transfer::run_identity_with_seal(&b, "h", &FakeHostSeal { tag: 2 }).unwrap();
    let s = FakeHostSeal { tag: 1 };
    assert!(transfer::run_peer_add_with_seal(&a, "h", &s, "../x", &b_id, false).is_err());
    assert!(transfer::run_peer_add_with_seal(&a, "h", &s, "me", &a_id, false).is_err());
    transfer::run_peer_add_with_seal(&a, "h", &s, "b", &b_id, false).unwrap();
    assert!(transfer::run_peer_add_with_seal(&a, "h", &s, "b", &b_id, false).is_err());
    assert!(transfer::run_peer_add_with_seal(&a, "h", &s, "b2", &b_id, false).is_err());
    assert!(transfer::run_peer_rm_with_seal(&a, "h", &FakeHostSeal { tag: 1 }, "b").unwrap());
    assert!(!transfer::run_peer_rm_with_seal(&a, "h", &FakeHostSeal { tag: 1 }, "b").unwrap());
    cleanup(&a);
    cleanup(&b);
}

#[test]
fn tokens_in_a_bundle_are_not_imported_unless_asked() {
    let (src, _) = vault_with("tsrc", 1, &[("app/A", b"1")]);
    let (dst, _) = vault_with("tdst", 2, &[]);
    // Remove the destination's own "app" service so the bundle's would be new.
    let (bytes, _) = transfer::run_export_with_seal(
        &src,
        "h",
        &FakeHostSeal { tag: 1 },
        PASS,
        FAST,
        &transfer::Selection::everything(),
    )
    .unwrap();
    let r = transfer::run_import_with_seal(
        &dst,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Passphrase(PASS),
        false,
        false,
        false,
    )
    .unwrap();
    assert!(r.tokens_withheld);
    assert_eq!((r.services_added, r.services_replaced), (0, 0));
    assert_eq!(r.tokens_offered.len(), 1);
    assert_eq!(r.entries_added, 1);
    cleanup(&src);
    cleanup(&dst);
}

#[test]
fn bundles_with_invalid_paths_or_ids_are_rejected_whole() {
    use cofferak_core::bundle::{seal_with_iterations, Bundle, BundleEntry};
    let (dst, _) = vault_with("bad", 2, &[]);
    for bad in ["", "/etc/x", "a//b", "a/../b", "a/./b", "line\nbreak"] {
        let b = Bundle {
            created_at: 0,
            source_fingerprint: String::new(),
            entries: vec![BundleEntry {
                path: bad.into(),
                value: b"v".to_vec(),
                version: 1,
                updated_at: 0,
            }],
            services: vec![],
        };
        let bytes = seal_with_iterations(&b, PASS, FAST).unwrap();
        let before = std::fs::read(vault_path(&dst)).unwrap();
        let e = transfer::run_import_with_seal(
            &dst,
            "h",
            &FakeHostSeal { tag: 2 },
            &bytes,
            transfer::ImportKey::Passphrase(PASS),
            false,
            false,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(e, CliError::Invalid(ref m) if m.contains("invalid path")),
            "{bad:?}: {e}"
        );
        assert_eq!(std::fs::read(vault_path(&dst)).unwrap(), before);
    }
    let b = Bundle {
        created_at: 0,
        source_fingerprint: String::new(),
        entries: vec![],
        services: vec![AccessToken {
            service_id: "../evil".into(),
            prefixes: vec!["app".into()],
            permission: Permission::ReadWrite,
            secret: [1; 32],
        }],
    };
    let bytes = seal_with_iterations(&b, PASS, FAST).unwrap();
    assert!(transfer::run_import_with_seal(
        &dst,
        "h",
        &FakeHostSeal { tag: 2 },
        &bytes,
        transfer::ImportKey::Passphrase(PASS),
        false,
        true,
        false,
    )
    .is_err());
    cleanup(&dst);
}
