//! Thin Unix-socket client speaking `arkeepd`'s newline-delimited JSON
//! protocol ([`crate::protocol`]).
//!
//! The protocol types come from `arkeepd`'s library target (ADR 0004),
//! re-exported as `crate::protocol` by `main.rs`, so the CLI and the
//! daemon share one definition.
//!
//! [`Client::send`] opens a fresh [`UnixStream`] per call rather than
//! holding a long-lived connection open. This is the simplest correct
//! option: a CLI invocation (`set`, `get`, ...) only ever needs to send
//! one request before the process exits, so there is no request volume to
//! amortize a persistent connection over. Pooling would add
//! reconnect-on-error and synchronization concerns for no benefit at this
//! call pattern — revisit only if a future caller sends many requests per
//! process lifetime.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use crate::protocol::{decode_response, encode, Request, Response};

/// A client for the daemon's Unix socket at `socket_path`.
pub struct Client {
    socket_path: PathBuf,
}

impl Client {
    /// Record `socket_path` for later use by [`Client::send`], after
    /// confirming the daemon is actually listening there — so a bad path
    /// or a daemon that isn't running is reported immediately here,
    /// rather than on the first real request.
    pub fn connect(socket_path: &Path) -> std::io::Result<Self> {
        // Open-then-drop: this connection is purely a reachability check.
        // `send` always opens its own fresh stream (see module doc
        // comment above).
        UnixStream::connect(socket_path)?;
        Ok(Client {
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// Send one request over a fresh connection and return the decoded
    /// response.
    ///
    /// Returns `Err` on any I/O failure, on a connection the daemon closes
    /// before writing a response line, or on a response line that fails
    /// to decode — never panics, and never returns a default/empty
    /// `Response` to paper over a failure.
    pub fn send(&self, req: &Request) -> std::io::Result<Response> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.write_all(&encode(req))?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed the connection without sending a response",
            ));
        }
        decode_response(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}
