//! **Dev/test-only daemon — not for production use.**
//!
//! Serves a real `Daemon` over a real Unix socket, with an in-memory
//! vault and a single pre-provisioned token — no disk persistence, no
//! `HostSeal`/Keychain/`systemd-creds` involved at all. Exists purely so
//! `scripts/sdk-smoke.sh` can prove each language SDK's *wire-protocol
//! client code* is correct against a real running daemon, independent
//! of the real binary's platform-specific key-sealing step (which has
//! its own, separately-tested, separately-proven path — see
//! `cofferak-core/tests/seal_{linux,macos}.rs` and `docs/PROGRESS.md`'s
//! "Known gaps" entry on cross-process Keychain access).
//!
//! Reads `COFFERAK_SOCKET` (required), `COFFERAK_TOKEN_SECRET_HEX` (required,
//! 64 lowercase hex chars), and `COFFERAK_TOKEN_PREFIX` (required) from the
//! environment. Exits as soon as it has bound the socket by printing
//! `ready` to stdout, then serves forever until killed.
//!
//! Also starts the server-mode TLS/TCP listener (ADR 0008) if
//! `COFFERAK_TLS_ADDR` (+ `COFFERAK_TLS_CERT`/`COFFERAK_TLS_KEY`, optionally
//! `COFFERAK_TLS_CLIENT_CA`) is set — the same opt-in env vars `main.rs`
//! reads, serving the same `daemon` over both transports at once.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::format::VaultFile;
use cofferakd::audit::AuditLog;
use cofferakd::daemon::Daemon;
use cofferakd::protocol::{decode_request, encode, Response};

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("dev-daemon: ${name} must be set");
        std::process::exit(1);
    })
}

fn main() {
    let socket_path = env_required("COFFERAK_SOCKET");
    let secret_hex = env_required("COFFERAK_TOKEN_SECRET_HEX");
    let prefix = env_required("COFFERAK_TOKEN_PREFIX");

    if secret_hex.len() != 64 {
        eprintln!("dev-daemon: COFFERAK_TOKEN_SECRET_HEX must be exactly 64 hex chars");
        std::process::exit(1);
    }
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&secret_hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("dev-daemon: COFFERAK_TOKEN_SECRET_HEX is not valid hex");
            std::process::exit(1);
        });
    }

    let dek = [0x42u8; 32]; // fixed, arbitrary — no sealing/persistence in this harness
    let (root_pubkey, _root_privkey) = cofferak_core::crypto::generate_root_keypair();
    let vault = VaultFile::new(root_pubkey);

    let mut tokens = BTreeMap::new();
    let token_key_hex = secret_hex.to_lowercase();
    tokens.insert(
        token_key_hex,
        AccessToken {
            service_id: "sdk-smoke-service".to_string(),
            prefixes: vec![prefix],
            permission: Permission::ReadWrite,
            secret,
        },
    );

    let audit_path = std::env::temp_dir().join(format!(
        "cofferakd-dev-daemon-audit-{}.jsonl",
        std::process::id()
    ));
    let audit = AuditLog::open(&audit_path).unwrap_or_else(|e| {
        eprintln!("dev-daemon: could not open audit log: {e}");
        std::process::exit(1);
    });

    let daemon = Arc::new(Mutex::new(Daemon::new(dek, vault, tokens, audit)));

    // Server mode (ADR 0008), same as the real `main.rs`: additive, only
    // if $COFFERAK_TLS_ADDR is set. Lets scripts/sdk-smoke.sh prove the
    // TLS/TCP transport too without needing the real HostSeal-backed
    // binary (see this file's module doc and ADR 0007 for why that's
    // not always possible non-interactively on macOS).
    match cofferakd::tls_server::resolve() {
        Ok(Some(tls_config)) => cofferakd::tls_server::start(tls_config, Arc::clone(&daemon)),
        Ok(None) => {}
        Err(msg) => {
            eprintln!("dev-daemon: {msg}");
            std::process::exit(1);
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap_or_else(|e| {
        eprintln!("dev-daemon: could not bind socket at {socket_path}: {e}");
        std::process::exit(1);
    });

    println!("ready");
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || handle_connection(stream, daemon));
    }
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
