//! Minimal Rust client SDK for cofferak.
//!
//! Connects to a running `cofferakd` over either its Unix socket or,
//! since ADR 0008 (server mode), TLS-wrapped TCP — and speaks the same
//! newline-delimited JSON protocol documented in
//! `cofferakd/src/protocol.rs` (`Request`/`Response`). This crate does not
//! depend on `cofferakd` or `cofferak-core` — it reimplements just the wire
//! format, so it stays usable as a standalone dependency for any Rust
//! service that wants to read/write secrets without shelling out to the
//! `cofferak` CLI binary.
//!
//! ```no_run
//! use cofferak_sdk::Client;
//!
//! let client = Client::connect("/run/cofferak/cofferakd.sock");
//! client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t").unwrap();
//! let value = client.get("my-token", "myapp/DB_PASSWORD").unwrap();
//! assert_eq!(value, b"s3cr3t");
//! ```

use serde::{Deserialize, Serialize};
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Errors a client call can return. Mirrors the daemon's response taxonomy
/// (`Denied`, `NotFound`, `Err(String)`) plus local I/O/protocol/TLS-setup
/// failures.
#[derive(Debug)]
pub enum SdkError {
    /// The token doesn't have access to this path, or the token is unknown.
    Denied,
    /// The requested path has no value set.
    NotFound,
    /// The daemon returned an error message.
    Remote(String),
    /// A local I/O failure connecting to or reading from the transport.
    Io(std::io::Error),
    /// The daemon's response wasn't valid JSON, or didn't match any known
    /// `Response` shape.
    Protocol(String),
    /// Loading certs/keys or building the TLS config failed (TLS
    /// transport only).
    Tls(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Denied => write!(f, "denied"),
            SdkError::NotFound => write!(f, "not found"),
            SdkError::Remote(msg) => write!(f, "remote error: {msg}"),
            SdkError::Io(e) => write!(f, "io error: {e}"),
            SdkError::Protocol(msg) => write!(f, "protocol error: {msg}"),
            SdkError::Tls(msg) => write!(f, "tls error: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SdkError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SdkError {
    fn from(e: std::io::Error) -> Self {
        SdkError::Io(e)
    }
}

/// Wire-format request, matching `cofferakd::protocol::Request` exactly
/// (externally-tagged enum, the default `serde` representation).
#[derive(Serialize)]
enum Request<'a> {
    Get {
        token: &'a str,
        path: &'a str,
    },
    Set {
        token: &'a str,
        path: &'a str,
        value: Vec<u8>,
    },
    Rm {
        token: &'a str,
        path: &'a str,
    },
    List {
        token: &'a str,
        prefix: &'a str,
    },
}

/// Wire-format response, matching `cofferakd::protocol::Response` exactly.
#[derive(Deserialize)]
enum Response {
    Value(Vec<u8>),
    Listed(Vec<String>),
    Ok,
    Denied,
    NotFound,
    Err(String),
}

/// Options for connecting over TLS/TCP (server mode, ADR 0008) instead
/// of the Unix socket.
pub struct TlsOptions {
    /// `host:port` to connect to (matches the daemon's `$COFFERAK_TLS_ADDR`).
    pub addr: String,
    /// The name to verify the server's certificate against (its subject/SAN).
    pub server_name: String,
    /// PEM file containing the CA that signed the server's certificate.
    /// cofferak's TLS is for a self-managed deployment, not the public
    /// web — there is no built-in trust of public root CAs.
    pub ca_cert_path: PathBuf,
    /// Client certificate + private key (PEM), required only if the
    /// server was started with `$COFFERAK_TLS_CLIENT_CA` (mutual TLS).
    pub client_cert_and_key: Option<(PathBuf, PathBuf)>,
}

enum Transport {
    Unix(PathBuf),
    Tls {
        addr: String,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    },
}

/// A client connected to one cofferakd endpoint — a Unix socket or, since
/// ADR 0008, a TLS/TCP address. Cheap to construct for the Unix case;
/// each call opens a fresh connection either way (matching `cofferakd`'s
/// own CLI client convention: simplest correct option, no
/// connection-pooling complexity).
pub struct Client {
    transport: Transport,
}

/// Hard ceiling on one response line — mirrors
/// `cofferakd::protocol::MAX_LINE_BYTES` (duplicated, not shared: this
/// crate deliberately has no dependency on `cofferakd`/`cofferak-core`, see
/// the module doc comment). A malicious or compromised daemon that
/// never terminates a response otherwise grows this buffer without
/// limit.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Read one newline-delimited line from `reader` into `buf` (cleared
/// first), refusing to grow past [`MAX_LINE_BYTES`]. See
/// `cofferakd::protocol::read_line_bounded` for the identical algorithm
/// and rationale.
fn read_line_bounded<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    buf.clear();
    let mut total = 0usize;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(total);
        }
        if let Some(newline_at) = available.iter().position(|&b| b == b'\n') {
            if total + newline_at + 1 > MAX_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response line exceeded the maximum allowed size",
                ));
            }
            buf.extend_from_slice(&available[..=newline_at]);
            total += newline_at + 1;
            reader.consume(newline_at + 1);
            return Ok(total);
        }
        let chunk_len = available.len();
        if total + chunk_len > MAX_LINE_BYTES {
            reader.consume(chunk_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response line exceeded the maximum allowed size",
            ));
        }
        buf.extend_from_slice(available);
        total += chunk_len;
        reader.consume(chunk_len);
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, SdkError> {
    let file = std::fs::File::open(path)
        .map_err(|e| SdkError::Tls(format!("reading {}: {e}", path.display())))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SdkError::Tls(format!("parsing certs in {}: {e}", path.display())))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, SdkError> {
    let file = std::fs::File::open(path)
        .map_err(|e| SdkError::Tls(format!("reading {}: {e}", path.display())))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|e| SdkError::Tls(format!("parsing private key in {}: {e}", path.display())))?
        .ok_or_else(|| SdkError::Tls(format!("no private key found in {}", path.display())))
}

impl Client {
    /// Build a client for the daemon's socket at `socket_path`. Does not
    /// connect yet — connection happens per call.
    pub fn connect(socket_path: impl AsRef<Path>) -> Self {
        Client {
            transport: Transport::Unix(socket_path.as_ref().to_path_buf()),
        }
    }

    /// Build a client for the daemon's TLS/TCP listener (server mode,
    /// ADR 0008). Loads and validates the CA (and, if given, client
    /// cert/key) eagerly, so a misconfiguration fails here rather than
    /// on the first call.
    pub fn connect_tls(options: TlsOptions) -> Result<Self, SdkError> {
        let ca_certs = load_certs(&options.ca_cert_path)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| SdkError::Tls(format!("adding CA cert: {e}")))?;
        }

        let builder = ClientConfig::builder().with_root_certificates(roots);
        let config = if let Some((cert_path, key_path)) = &options.client_cert_and_key {
            let certs = load_certs(cert_path)?;
            let key = load_private_key(key_path)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| SdkError::Tls(format!("invalid client certificate/key: {e}")))?
        } else {
            builder.with_no_client_auth()
        };

        let server_name = ServerName::try_from(options.server_name)
            .map_err(|e| SdkError::Tls(format!("invalid server name: {e}")))?
            .to_owned();

        Ok(Client {
            transport: Transport::Tls {
                addr: options.addr,
                server_name,
                config: Arc::new(config),
            },
        })
    }

    fn send(&self, request: &Request) -> Result<Response, SdkError> {
        let mut bytes = serde_json::to_vec(request)
            .map_err(|e| SdkError::Protocol(format!("failed to encode request: {e}")))?;
        bytes.push(b'\n');

        let mut line = Vec::new();
        match &self.transport {
            Transport::Unix(socket_path) => {
                let mut stream = UnixStream::connect(socket_path)?;
                stream.write_all(&bytes)?;
                let mut reader = BufReader::new(stream);
                read_line_bounded(&mut reader, &mut line)?;
            }
            Transport::Tls {
                addr,
                server_name,
                config,
            } => {
                let tcp = TcpStream::connect(addr)?;
                // A malicious or hung server otherwise blocks the
                // caller's thread indefinitely — bound it, matching the
                // daemon's own stance on its listeners.
                let timeout = Some(std::time::Duration::from_secs(30));
                let _ = tcp.set_read_timeout(timeout);
                let _ = tcp.set_write_timeout(timeout);
                let conn = ClientConnection::new(Arc::clone(config), server_name.clone())
                    .map_err(|e| SdkError::Tls(format!("starting TLS handshake: {e}")))?;
                let tls = StreamOwned::new(conn, tcp);
                let mut reader = BufReader::new(tls);
                reader.get_mut().write_all(&bytes)?;
                read_line_bounded(&mut reader, &mut line)?;
            }
        }
        let line = String::from_utf8(line)
            .map_err(|e| SdkError::Protocol(format!("response was not valid UTF-8: {e}")))?;

        serde_json::from_str(&line)
            .map_err(|e| SdkError::Protocol(format!("failed to decode response: {e}")))
    }

    fn check_ok(response: Response) -> Result<(), SdkError> {
        match response {
            Response::Ok => Ok(()),
            Response::Denied => Err(SdkError::Denied),
            Response::NotFound => Err(SdkError::NotFound),
            Response::Err(msg) => Err(SdkError::Remote(msg)),
            other => Err(SdkError::Protocol(format!(
                "unexpected response to a write/delete request: {other:?}"
            ))),
        }
    }

    /// Read a secret's value.
    pub fn get(&self, token: &str, path: &str) -> Result<Vec<u8>, SdkError> {
        match self.send(&Request::Get { token, path })? {
            Response::Value(bytes) => Ok(bytes),
            Response::Denied => Err(SdkError::Denied),
            Response::NotFound => Err(SdkError::NotFound),
            Response::Err(msg) => Err(SdkError::Remote(msg)),
            other => Err(SdkError::Protocol(format!(
                "unexpected response to Get: {other:?}"
            ))),
        }
    }

    /// Write a secret's value. Requires a read-write token.
    pub fn set(&self, token: &str, path: &str, value: &[u8]) -> Result<(), SdkError> {
        let response = self.send(&Request::Set {
            token,
            path,
            value: value.to_vec(),
        })?;
        Self::check_ok(response)
    }

    /// Remove a secret. Requires a read-write token.
    pub fn rm(&self, token: &str, path: &str) -> Result<(), SdkError> {
        let response = self.send(&Request::Rm { token, path })?;
        Self::check_ok(response)
    }

    /// List secret paths under `prefix`.
    pub fn list(&self, token: &str, prefix: &str) -> Result<Vec<String>, SdkError> {
        match self.send(&Request::List { token, prefix })? {
            Response::Listed(paths) => Ok(paths),
            Response::Denied => Err(SdkError::Denied),
            Response::Err(msg) => Err(SdkError::Remote(msg)),
            other => Err(SdkError::Protocol(format!(
                "unexpected response to List: {other:?}"
            ))),
        }
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Value(_) => write!(f, "Value(..)"),
            Response::Listed(v) => write!(f, "Listed({v:?})"),
            Response::Ok => write!(f, "Ok"),
            Response::Denied => write!(f, "Denied"),
            Response::NotFound => write!(f, "NotFound"),
            Response::Err(e) => write!(f, "Err({e:?})"),
        }
    }
}
