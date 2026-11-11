//! End-to-end fresh-host test (Task 16): drives the full lifecycle —
//! `init --root` -> `init --host` -> `enroll-service` -> a real
//! `Daemon`/`UnixListener` seeded from the resulting vault+token -> `set`/
//! `get` over a real `Client` -> a denied `get` outside the token's
//! prefix -> `audit tail` -- entirely through the public functions Tasks
//! 11-15 produced, not through `clap`'s argument parsing and not through
//! any reimplementation of daemon/ACL logic.
//!
//! `cofferak-cli` has no library target, so `commands/init.rs`,
//! `commands/enroll.rs`, `commands/secrets.rs`, `commands/audit.rs`, and
//! `src/client.rs` are pulled in directly via `#[path]`. The daemon-side
//! `protocol`/`audit`/`daemon` modules come from the real `cofferakd`
//! library crate and are re-exported at this test's crate root, so the
//! CLI files' `crate::protocol` paths resolve to the very same types the
//! `Daemon` uses — one definition of each, exactly as in the real binaries.
//!
//! The socket server itself (bind a `UnixListener`, spawn one thread per
//! connection, decode/dispatch/encode each line through
//! `Daemon::handle_request`) is the same deliberately-duplicated, trimmed
//! copy of `cofferakd/src/main.rs`'s accept loop that `cli_secrets.rs`
//! already uses.

use cofferakd::audit;
#[allow(dead_code)] // each test binary uses only a subset of these shared source modules
#[path = "../src/commands/audit.rs"]
mod audit_cmd;
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

use cofferak_core::acl::Permission;
use cofferak_core::crypto::unwrap_dek_for_host;
use cofferak_core::format::VaultFile;
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

use audit::AuditLog;
use client::Client;
use daemon::{token_key, Daemon};
use enroll::run_enroll_service_with_seal;
use init::{run_init_host_with_seal, run_init_root, vault_path, CliError};
use protocol::{decode_request, encode, Response};

/// Same trivial, deterministic, in-memory `HostSeal` fake used across
/// Tasks 11-13's own tests (`cli_init.rs`/`cli_enroll.rs`/
/// `cli_secrets.rs`) — this is the fake `HostSeal` test double the task
/// brief calls for, keeping this test deterministic and independent of
/// `systemd-creds`/Keychain being available in CI. The real platform
/// backends are separately covered by Task 5/6's own tests.
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
        "cofferak-cli-e2e-fresh-host-{}-{}-{}-{tag}",
        std::process::id(),
        nanos,
        n
    ))
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Short, `/tmp`-rooted socket path: `AF_UNIX` paths have a small fixed
/// buffer (~104 bytes on macOS/BSD), which `std::env::temp_dir()`'s
/// per-process subdirectories can exceed, so sockets get their own
/// deliberately-short naming scheme instead of reusing `temp_dir` (same
/// convention as `cli_secrets.rs`).
fn short_socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    PathBuf::from(format!(
        "/tmp/cofferak-cli-e2e-{}-{}-{tag}.sock",
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
/// protocol — a trimmed copy of `cofferakd/src/main.rs`'s own accept
/// loop/`handle_connection` (private to that binary, so duplicated here
/// rather than imported; same as `cli_secrets.rs`). Returns once the
/// socket is bound, so a `Client::connect` issued right after this
/// returns will not race the bind.
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

#[test]
fn fresh_host_lifecycle_init_enroll_set_get_deny_audit() {
    let dir = temp_dir("lifecycle");

    // init --root
    run_init_root(&dir).expect("init --root should succeed");

    // init --host "a" (fake seal)
    let seal_a = FakeHostSeal { tag: 0xA1 };
    run_init_host_with_seal(&dir, "a", &seal_a).expect("init --host a should succeed");

    // enroll-service (myapp, prefix myapp, ReadWrite)
    let token = run_enroll_service_with_seal(
        &dir,
        "a",
        &seal_a,
        "myapp",
        vec!["myapp".to_string()],
        Permission::ReadWrite,
    )
    .expect("enroll-service should succeed");

    // Spin up a real Daemon behind a real UnixListener, seeded from the
    // resulting VaultFile and the returned token — the same way a real
    // `cofferakd` would be seeded by reading `vault.cofferak` and unsealing
    // this host's own blob.
    let vault = VaultFile::load(&vault_path(&dir)).expect("load freshly-enrolled vault");
    let host_wrap = vault.hosts["a"].clone();
    let sealed_bytes = std::fs::read(dir.join("hosts/a.seal")).expect("read host a's seal");
    let host_key = seal_a
        .unseal(&SealedBlob(sealed_bytes))
        .expect("unseal host a's key");
    let dek = unwrap_dek_for_host(&host_wrap, "a", &host_key).expect("unwrap the vault DEK");

    let mut tokens = BTreeMap::new();
    tokens.insert(token_key(&token.secret), token.clone());

    let audit_path = dir.join("audit.jsonl");
    let audit = AuditLog::open(&audit_path).expect("open daemon audit log");

    let daemon = Daemon::new(dek, vault, tokens, audit);
    let socket_path = short_socket_path("lifecycle");
    let _server = spawn_daemon_server(daemon, socket_path.clone());

    let client = Client::connect(&socket_path).expect("connect to the real daemon socket");
    let token_str = token_key(&token.secret);

    // set myapp/OPENAI_API_KEY, get it back, assert equality.
    secrets::run_set(
        &client,
        &token_str,
        "myapp/OPENAI_API_KEY",
        b"sk-fresh-host-e2e".to_vec(),
    )
    .expect("set myapp/OPENAI_API_KEY should succeed");

    let got = secrets::run_get(&client, &token_str, "myapp/OPENAI_API_KEY")
        .expect("get myapp/OPENAI_API_KEY should succeed");
    assert_eq!(got, b"sk-fresh-host-e2e".to_vec());

    // get on other/SECRET with the same token must be denied: it is
    // outside the token's "myapp" prefix.
    let denied = secrets::run_get(&client, &token_str, "other/SECRET");
    assert!(
        matches!(denied, Err(CliError::Denied)),
        "expected Err(CliError::Denied), got {denied:?}"
    );

    // audit tail must contain both allowed entries and the denied get,
    // with matching result fields.
    let entries =
        audit_cmd::run_audit_tail(&audit_path, 20).expect("run_audit_tail should succeed");

    let has_allowed_set = entries.iter().any(|e| {
        e.service_id == "myapp"
            && e.action == "set"
            && e.path == "myapp/OPENAI_API_KEY"
            && e.result == "ok"
    });
    assert!(
        has_allowed_set,
        "expected an allowed set entry, got {entries:?}"
    );

    let has_allowed_get = entries.iter().any(|e| {
        e.service_id == "myapp"
            && e.action == "get"
            && e.path == "myapp/OPENAI_API_KEY"
            && e.result == "ok"
    });
    assert!(
        has_allowed_get,
        "expected an allowed get entry, got {entries:?}"
    );

    let has_denied_get = entries.iter().any(|e| {
        e.service_id == "myapp"
            && e.action == "get"
            && e.path == "other/SECRET"
            && e.result == "denied"
    });
    assert!(
        has_denied_get,
        "expected a denied get entry, got {entries:?}"
    );

    cleanup(&dir);
}
