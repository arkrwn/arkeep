//! Server mode (ADR 0008): the same `Request`/`Response` protocol the
//! Unix socket speaks, also reachable over TLS-wrapped TCP. Additive —
//! enabling this never disables or changes the Unix socket path.
//!
//! Enabled by setting `$COFFERAK_TLS_ADDR` (e.g. `0.0.0.0:8443`).
//! `$COFFERAK_TLS_CERT`/`$COFFERAK_TLS_KEY` (PEM files) are then required.
//! `$COFFERAK_TLS_CLIENT_CA` (PEM file) is optional: when set, the server
//! requires and verifies a client certificate signed by that CA (mutual
//! TLS) in addition to the unconditional per-service access token check
//! `Daemon::handle_request` already performs — TLS adds transport
//! confidentiality/integrity (and optionally client identity), it is
//! never a substitute for the token.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::daemon::Daemon;
use crate::protocol::{decode_request, encode, Response};

/// What `$COFFERAK_TLS_ADDR` and friends resolved to, if server mode is
/// enabled. Returned by [`resolve`] so the caller can report a clear
/// error for a partially-set configuration (e.g. `COFFERAK_TLS_ADDR` set
/// but `COFFERAK_TLS_CERT` missing) before doing anything else.
pub struct TlsServerConfig {
    pub addr: String,
    pub cert_path: String,
    pub key_path: String,
    pub client_ca_path: Option<String>,
}

/// Reads the `COFFERAK_TLS_*` environment variables. Returns `Ok(None)` if
/// server mode isn't requested at all (`COFFERAK_TLS_ADDR` unset). Returns
/// `Err` with a clear message for a partially-set configuration — never
/// silently starts with only some of what was asked for.
pub fn resolve() -> Result<Option<TlsServerConfig>, String> {
    let Ok(addr) = std::env::var("COFFERAK_TLS_ADDR") else {
        return Ok(None);
    };
    let cert_path = std::env::var("COFFERAK_TLS_CERT")
        .map_err(|_| "COFFERAK_TLS_ADDR is set but COFFERAK_TLS_CERT is not".to_string())?;
    let key_path = std::env::var("COFFERAK_TLS_KEY")
        .map_err(|_| "COFFERAK_TLS_ADDR is set but COFFERAK_TLS_KEY is not".to_string())?;
    let client_ca_path = std::env::var("COFFERAK_TLS_CLIENT_CA").ok();
    Ok(Some(TlsServerConfig {
        addr,
        cert_path,
        key_path,
        client_ca_path,
    }))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {path}: {e}"))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parsing certs in {path}: {e}"))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {path}: {e}"))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|e| format!("parsing private key in {path}: {e}"))?
        .ok_or_else(|| format!("no private key found in {path}"))
}

fn build_server_config(config: &TlsServerConfig) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;

    let builder = rustls::ServerConfig::builder();
    let builder = if let Some(ca_path) = &config.client_ca_path {
        let ca_certs = load_certs(ca_path)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| format!("adding client CA from {ca_path}: {e}"))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("building client cert verifier: {e}"))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };

    let server_config = builder
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid server certificate/key: {e}"))?;
    Ok(Arc::new(server_config))
}

/// Start the TLS/TCP listener on its own thread, serving `daemon` the
/// same way the Unix socket path does. Exits the process with a clear
/// error on any setup failure (bind, cert load, config build) — mirrors
/// the Unix socket listener's own `unwrap_or_else(... exit(1))` style in
/// `main.rs`, so a server-mode misconfiguration fails loudly at startup
/// rather than silently running without it.
pub fn start(config: TlsServerConfig, daemon: Arc<Mutex<Daemon>>) {
    let server_config = build_server_config(&config).unwrap_or_else(|e| {
        eprintln!("cofferakd: TLS server config error: {e}");
        std::process::exit(1);
    });

    let listener = TcpListener::bind(&config.addr).unwrap_or_else(|e| {
        eprintln!(
            "cofferakd: could not bind TLS listener at {}: {e}",
            config.addr
        );
        std::process::exit(1);
    });

    println!(
        "cofferakd: server mode listening on {} (TLS{})",
        config.addr,
        if config.client_ca_path.is_some() {
            ", client certs required"
        } else {
            ""
        }
    );

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(tcp) = stream else { continue };
            let daemon = Arc::clone(&daemon);
            let server_config = Arc::clone(&server_config);
            std::thread::spawn(move || handle_tls_connection(tcp, server_config, daemon));
        }
    });
}

fn handle_tls_connection(
    tcp: TcpStream,
    server_config: Arc<ServerConfig>,
    daemon: Arc<Mutex<Daemon>>,
) {
    // Network-reachable, unlike the Unix socket — bound how long one
    // stalled/slow client can hold a thread. A client that connects and
    // never sends anything, or never reads the response, is dropped
    // rather than parked forever (a cheap mitigation for a
    // slowloris-style thread-exhaustion DoS against this listener).
    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let _ = tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)));

    let conn = match ServerConnection::new(server_config) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let tls = StreamOwned::new(conn, tcp);

    // `BufReader` takes ownership of `tls` so its internal buffer
    // persists across loop iterations (a per-iteration `BufReader` would
    // silently drop any bytes of the *next* request already read ahead
    // into the buffer by the bounded read below). Writes go through
    // `reader.get_mut()`, which hands back `&mut StreamOwned` without
    // touching the read buffer — both directions share the one
    // `ServerConnection`, as TLS record state requires.
    let mut reader = BufReader::new(tls);
    let mut line = Vec::new();
    loop {
        // Bounded (`protocol::MAX_LINE_BYTES`), not `read_until`: this
        // listener is network-reachable, so an unbounded read is a real
        // memory-exhaustion DoS from a client that never sends `\n`.
        match crate::protocol::read_line_bounded(&mut reader, &mut line) {
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

        if reader.get_mut().write_all(&encode(&response)).is_err() {
            break;
        }
    }
}
