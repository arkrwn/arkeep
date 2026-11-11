//! Server mode (ADR 0008): the same `Request`/`Response` protocol the
//! Unix socket speaks, also reachable over TLS-wrapped TCP. Additive —
//! enabling this never disables or changes the Unix socket path.
//!
//! Enabled by setting `$COFFERAK_TLS_ADDR` (e.g. `0.0.0.0:8443`).
//! `$COFFERAK_TLS_CERT`/`$COFFERAK_TLS_KEY` (PEM) and
//! `$COFFERAK_TLS_CLIENT_CA` (PEM) are then all required: **mutual TLS is
//! mandatory** (ADR 0011). A peer without a client certificate signed by
//! that CA fails the handshake before it can send a single request, and
//! the per-service access token is still checked on every request on top.
//!
//! The TLS stack is pinned to the strongest settings cofferak's clients all
//! support ([`hardened_provider`]): TLS 1.3 only, the AES-256-GCM-SHA384
//! cipher suite only, and key exchange limited to ML-KEM-1024
//! (preferred), the X25519MLKEM768 post-quantum hybrid, or classical P-384
//! as the fallback.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
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
    pub client_ca_path: String,
    /// Maximum concurrent TLS connections (`$COFFERAK_TLS_MAX_CONNECTIONS`).
    pub max_connections: usize,
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
    let client_ca_path = std::env::var("COFFERAK_TLS_CLIENT_CA")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            "COFFERAK_TLS_ADDR is set but COFFERAK_TLS_CLIENT_CA is not: server mode requires \
             mutual TLS (a CA that signs every client certificate), see docs/adr/0011"
                .to_string()
        })?;
    let max_connections = parse_max_connections(
        std::env::var("COFFERAK_TLS_MAX_CONNECTIONS")
            .ok()
            .as_deref(),
    )?;
    Ok(Some(TlsServerConfig {
        addr,
        cert_path,
        key_path,
        client_ca_path,
        max_connections,
    }))
}

/// `$COFFERAK_TLS_MAX_CONNECTIONS`: a positive integer, default
/// [`DEFAULT_MAX_CONNECTIONS`].
fn parse_max_connections(raw: Option<&str>) -> Result<usize, String> {
    match raw {
        None | Some("") => Ok(DEFAULT_MAX_CONNECTIONS),
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!(
                "COFFERAK_TLS_MAX_CONNECTIONS must be a positive integer, got {s:?}"
            )),
        },
    }
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

/// The TLS crypto provider every server-mode connection uses: AWS-LC
/// (FIPS 140-3 validated module) restricted to
///
/// - cipher suite **TLS13_AES_256_GCM_SHA384** only (CNSA: AES-256, SHA-384);
/// - key exchange **MLKEM1024** (post-quantum, the only ML-KEM parameter
///   set CNSA 2.0 approves; preferred), then **X25519MLKEM768** (the
///   IETF post-quantum hybrid that Go and OpenSSL 3.5+ clients offer),
///   then **SECP384R1** (CNSA 1.0 classical fallback for TLS libraries
///   without post-quantum support).
///
/// Combined with `TLS13` as the only protocol version in
/// [`build_server_config`].
pub fn hardened_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{cipher_suite, default_provider, kx_group};
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            kx_group::MLKEM1024,
            kx_group::X25519MLKEM768,
            kx_group::SECP384R1,
        ],
        ..default_provider()
    }
}

fn build_server_config(config: &TlsServerConfig) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;
    let provider = Arc::new(hardened_provider());

    let ca_path = &config.client_ca_path;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        roots
            .add(cert)
            .map_err(|e| format!("adding client CA from {ca_path}: {e}"))?;
    }
    if roots.is_empty() {
        return Err(format!("no CA certificate found in {ca_path}"));
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("building client cert verifier: {e}"))?;

    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_client_cert_verifier(verifier)
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
        "cofferakd: server mode listening on {} (TLS 1.3, mutual TLS required)",
        config.addr
    );

    let limiter = ConnectionLimiter::new(config.max_connections);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(tcp) = stream else { continue };
            // Over the limit: close immediately instead of spawning a
            // thread, so a flood of connections can't exhaust threads or
            // memory. Legitimate clients just retry.
            let Some(slot) = limiter.try_acquire() else {
                let _ = tcp.shutdown(std::net::Shutdown::Both);
                continue;
            };
            let daemon = Arc::clone(&daemon);
            let server_config = Arc::clone(&server_config);
            std::thread::spawn(move || {
                let _slot = slot;
                handle_tls_connection(tcp, server_config, daemon);
            });
        }
    });
}

/// Default cap on concurrent TLS connections; override with
/// `$COFFERAK_TLS_MAX_CONNECTIONS`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Counts live connections and refuses new ones past `max`.
#[derive(Clone)]
pub struct ConnectionLimiter {
    live: Arc<AtomicUsize>,
    max: usize,
}

/// One held connection slot; released when dropped (including when the
/// connection thread panics and unwinds).
pub struct ConnectionSlot {
    live: Arc<AtomicUsize>,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Self {
        ConnectionLimiter {
            live: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    pub fn try_acquire(&self) -> Option<ConnectionSlot> {
        let mut current = self.live.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnectionSlot {
                        live: Arc::clone(&self.live),
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_refuses_past_max_and_frees_slots_on_drop() {
        let limiter = ConnectionLimiter::new(2);
        let a = limiter.try_acquire().expect("slot 1");
        let _b = limiter.try_acquire().expect("slot 2");
        assert!(limiter.try_acquire().is_none(), "third must be refused");
        drop(a);
        assert!(limiter.try_acquire().is_some(), "freed slot is reusable");
    }

    #[test]
    fn parse_max_connections_rejects_zero_and_garbage() {
        assert_eq!(parse_max_connections(None), Ok(DEFAULT_MAX_CONNECTIONS));
        assert_eq!(parse_max_connections(Some("64")), Ok(64));
        assert!(parse_max_connections(Some("0")).is_err());
        assert!(parse_max_connections(Some("lots")).is_err());
    }
}
