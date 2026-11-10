//! Minimal Rust client SDK for cofferak.
//!
//! Connects to a running `cofferakd` over its Unix socket and speaks the
//! same newline-delimited JSON protocol documented in
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
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Errors a client call can return. Mirrors the daemon's response taxonomy
/// (`Denied`, `NotFound`, `Err(String)`) plus local I/O/protocol failures.
#[derive(Debug)]
pub enum SdkError {
    /// The token doesn't have access to this path, or the token is unknown.
    Denied,
    /// The requested path has no value set.
    NotFound,
    /// The daemon returned an error message.
    Remote(String),
    /// A local I/O failure connecting to or reading from the socket.
    Io(std::io::Error),
    /// The daemon's response wasn't valid JSON, or didn't match any known
    /// `Response` shape.
    Protocol(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Denied => write!(f, "denied"),
            SdkError::NotFound => write!(f, "not found"),
            SdkError::Remote(msg) => write!(f, "remote error: {msg}"),
            SdkError::Io(e) => write!(f, "io error: {e}"),
            SdkError::Protocol(msg) => write!(f, "protocol error: {msg}"),
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

/// A client connected to one cofferakd Unix socket. Cheap to construct —
/// each call opens a fresh connection (matching `cofferakd`'s own CLI
/// client convention: simplest correct option, no connection-pooling
/// complexity).
pub struct Client {
    socket_path: PathBuf,
}

impl Client {
    /// Build a client for the daemon's socket at `socket_path`. Does not
    /// connect yet — connection happens per call.
    pub fn connect(socket_path: impl AsRef<Path>) -> Self {
        Client {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    fn send(&self, request: &Request) -> Result<Response, SdkError> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let mut bytes = serde_json::to_vec(request)
            .map_err(|e| SdkError::Protocol(format!("failed to encode request: {e}")))?;
        bytes.push(b'\n');
        stream.write_all(&bytes)?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
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
