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

/// Parse a single request line.
pub fn decode_request(line: &[u8]) -> Result<Request, serde_json::Error> {
    serde_json::from_slice(line)
}

/// Parse a single response line.
pub fn decode_response(line: &[u8]) -> Result<Response, serde_json::Error> {
    serde_json::from_slice(line)
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
}
