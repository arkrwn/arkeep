//! Newline-delimited JSON protocol spoken over the daemon's Unix socket.

// Consumers (daemon core, CLI client) land in later tasks.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// A client request to the daemon.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Get {
        token: String,
        path: String,
    },
    Set {
        token: String,
        path: String,
        value: Vec<u8>,
    },
    Rm {
        token: String,
        path: String,
    },
    List {
        token: String,
        prefix: String,
    },
}

/// A daemon response to a client request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Response {
    Value(Vec<u8>),
    Listed(Vec<String>),
    Ok,
    Denied,
    NotFound,
    Err(String),
}

/// Serialize a message as one JSON line, terminated by `\n`.
pub fn encode(msg: &impl Serialize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(msg).expect("protocol messages always serialize");
    bytes.push(b'\n');
    bytes
}

/// Encode `response` for the wire and wipe the plaintext value it carried.
/// The caller wipes the returned bytes after sending them.
pub fn respond(response: Response) -> Vec<u8> {
    let out = encode(&response);
    if let Response::Value(mut v) = response {
        zeroize::Zeroize::zeroize(&mut v);
    }
    out
}

/// Parse a single request line.
pub fn decode_request(line: &[u8]) -> Result<Request, serde_json::Error> {
    serde_json::from_slice(line)
}

/// Parse a single response line.
pub fn decode_response(line: &[u8]) -> Result<Response, serde_json::Error> {
    serde_json::from_slice(line)
}

/// Hard ceiling on one request/response line, enforced by
/// [`read_line_bounded`]. Generous for any realistic secret value while
/// still bounding memory a single connection can force the process to
/// allocate — a client that never sends `\n` (or sends one absurdly
/// long line) otherwise grows the read buffer without limit. This
/// matters most for the network-reachable TLS listener (server mode,
/// ADR 0008), but is enforced for every transport (Unix socket
/// included) for one consistent, auditable limit rather than a
/// per-transport exception.
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Largest secret value the daemon accepts (enforced in the daemon, not
/// only in clients). A value is sent as a JSON array of numbers, up to four
/// characters per byte, so this fits well inside [`MAX_LINE_BYTES`].
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Hard limit on how long one client connection may stay open, on both the
/// Unix socket and TLS: a slow or stalled client can't hold a slot longer.
pub const CONNECTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Close `stream` when `deadline` passes, unless the returned guard is
/// dropped first (the connection finished). One short-lived thread per
/// connection, woken as soon as the connection ends.
pub fn enforce_deadline<S: Shutdownable + Send + 'static>(
    stream: S,
    deadline: std::time::Duration,
) -> std::sync::mpsc::Sender<()> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(deadline) {
            stream.shutdown_both();
        }
    });
    tx
}

/// A connection that can be shut down from another thread.
pub trait Shutdownable {
    fn shutdown_both(&self);
}

impl Shutdownable for std::os::unix::net::UnixStream {
    fn shutdown_both(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

impl Shutdownable for std::net::TcpStream {
    fn shutdown_both(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

/// Read one newline-delimited line from `reader` into `buf` (which is
/// cleared first), refusing to grow past [`MAX_LINE_BYTES`]. Returns
/// `Ok(0)` on a clean EOF with nothing read (matching
/// `BufRead::read_until`'s convention), `Ok(n)` for a line of `n` bytes
/// (including the trailing `\n` if one was found before the limit), or
/// `Err` if the limit was hit before a newline, or on any I/O error.
/// Hitting the limit is reported as `InvalidData`, not silently
/// truncated — the caller closes the connection rather than trying to
/// parse a partial line as JSON.
pub fn read_line_bounded<R: std::io::BufRead>(
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
            return Ok(total); // EOF
        }
        if let Some(newline_at) = available.iter().position(|&b| b == b'\n') {
            if total + newline_at + 1 > MAX_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request line exceeded the maximum allowed size",
                ));
            }
            buf.extend_from_slice(&available[..=newline_at]);
            total += newline_at + 1;
            reader.consume(newline_at + 1);
            return Ok(total);
        }
        let chunk_len = available.len();
        if total + chunk_len > MAX_LINE_BYTES {
            // Drain what's buffered so the stream itself isn't left in
            // an inconsistent state, then report the overflow.
            reader.consume(chunk_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request line exceeded the maximum allowed size",
            ));
        }
        buf.extend_from_slice(available);
        total += chunk_len;
        reader.consume(chunk_len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_variants_round_trip() {
        let requests = vec![
            Request::Get {
                token: "tok".into(),
                path: "a/b".into(),
            },
            Request::Set {
                token: "tok".into(),
                path: "a/b".into(),
                value: vec![0, 1, 2, 255],
            },
            Request::Rm {
                token: "tok".into(),
                path: "a/b".into(),
            },
            Request::List {
                token: "tok".into(),
                prefix: "a/".into(),
            },
        ];
        for req in requests {
            let bytes = encode(&req);
            assert_eq!(bytes.last(), Some(&b'\n'));
            let decoded = decode_request(&bytes).expect("request should decode");
            assert_eq!(format!("{decoded:?}"), format!("{req:?}"));
        }
    }

    #[test]
    fn response_variants_round_trip() {
        let responses = vec![
            Response::Value(vec![9, 8, 7]),
            Response::Listed(vec!["a".into(), "b/c".into()]),
            Response::Ok,
            Response::Denied,
            Response::NotFound,
            Response::Err("boom".into()),
        ];
        for resp in responses {
            let bytes = encode(&resp);
            assert_eq!(bytes.last(), Some(&b'\n'));
            let decoded = decode_response(&bytes).expect("response should decode");
            assert_eq!(decoded, resp);
        }
    }

    #[test]
    fn decode_request_malformed_is_error_not_panic() {
        assert!(decode_request(b"not json").is_err());
        assert!(decode_request(b"").is_err());
        assert!(decode_request(b"{\"Unknown\":{}}").is_err());
    }

    #[test]
    fn decode_response_malformed_is_error_not_panic() {
        assert!(decode_response(b"not json").is_err());
    }

    #[test]
    fn read_line_bounded_reads_one_line_and_leaves_the_rest_buffered() {
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(b"first\nsecond\n".to_vec()));
        let mut buf = Vec::new();
        let n = read_line_bounded(&mut reader, &mut buf).expect("first read should succeed");
        assert_eq!(n, 6);
        assert_eq!(buf, b"first\n");
        let n = read_line_bounded(&mut reader, &mut buf).expect("second read should succeed");
        assert_eq!(n, 7);
        assert_eq!(buf, b"second\n");
    }

    #[test]
    fn read_line_bounded_returns_zero_on_clean_eof() {
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
        let mut buf = Vec::new();
        let n = read_line_bounded(&mut reader, &mut buf).expect("eof should not be an error");
        assert_eq!(n, 0);
    }

    #[test]
    fn read_line_bounded_rejects_a_line_with_no_newline_past_the_limit() {
        // A tiny reader with a byte stream larger than MAX_LINE_BYTES and
        // no '\n' anywhere — simulating a client that never terminates
        // its line. Use a small artificial cap via a wrapper is overkill
        // here; instead feed slightly more than MAX_LINE_BYTES of plain
        // bytes through the real constant so the test is a real,
        // non-mocked proof the cap is enforced, not a stand-in for it.
        let oversized = vec![b'x'; MAX_LINE_BYTES + 1];
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(oversized));
        let mut buf = Vec::new();
        let result = read_line_bounded(&mut reader, &mut buf);
        assert!(result.is_err(), "expected an error, got {result:?}");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_line_bounded_rejects_a_line_that_hits_the_limit_exactly_at_the_newline() {
        // A line whose newline would land exactly one byte past the cap.
        let mut data = vec![b'x'; MAX_LINE_BYTES];
        data.push(b'\n');
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
        let mut buf = Vec::new();
        let result = read_line_bounded(&mut reader, &mut buf);
        assert!(result.is_err(), "expected an error, got {result:?}");
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::enforce_deadline;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    #[test]
    fn a_stalled_connection_is_closed_at_the_deadline() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let _guard = enforce_deadline(server.try_clone().unwrap(), Duration::from_millis(200));
        // The client never sends anything; reading from the server side
        // must end (EOF) once the deadline shuts the socket down.
        let mut s = server;
        let mut buf = [0u8; 1];
        let n = s.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0);
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert!(start.elapsed() < Duration::from_secs(5));
        let _ = client.read(&mut buf);
    }

    #[test]
    fn a_finished_connection_is_left_alone() {
        let (server, _client) = UnixStream::pair().unwrap();
        let guard = enforce_deadline(server.try_clone().unwrap(), Duration::from_millis(100));
        drop(guard);
        std::thread::sleep(Duration::from_millis(200));
        server.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 1];
        let err = (&server).read(&mut buf).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::WouldBlock,
            "socket must still be open"
        );
    }
}
